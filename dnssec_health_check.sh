#!/usr/bin/env bash
# DNS + Email posture checker (expert edition)
# Goals: reproduce and strengthen the legacy checker coverage with resilient parsing, clear reporting,
#        and battle-tested operational guard rails.

set -u

VERSION="1.0"

# Defaults (may be overridden by env/flags)
DOMAIN="${DOMAIN:-}"
INTERVAL="${INTERVAL:-0}"
DKIM_SELECTORS_RAW="${DKIM_SELECTORS:-selector1 selector2}"
AUTO_NS="${AUTO_NS:-1}"
AUTHORITATIVES_OVERRIDE="${AUTHORITATIVES:-}"

RESOLVERS=(
  8.8.8.8
  8.8.4.4
  1.1.1.1
  1.0.0.1
  9.9.9.9
  149.112.112.112
  64.6.64.6
  208.67.222.222
)

OK="✅"; WARN="⚠️"; BAD="❌"; NOTSET="🚫"; INFO="ℹ️"

# ----- utilities -----

die(){ printf 'ERROR: %s\n' "$1" >&2; exit 1; }

require_tool(){ command -v "$1" >/dev/null 2>&1 || die "Missing required tool: $1"; }

trim(){ printf '%s' "$1" | awk '{$1=$1;print}'; }

lower(){ printf '%s' "$1" | tr 'A-Z' 'a-z'; }

split_list(){
  # comma/space separated -> newline
  if [[ $# -gt 0 ]]; then
    printf '%s' "$1"
  else
    cat
  fi | tr ',\t' '  ' | tr -s ' ' '\n' | sed '/^$/d'
}

sanitize_host_list(){
  if [[ $# -gt 0 ]]; then
    split_list "$1"
  else
    split_list
  fi | tr 'A-Z' 'a-z' | sed 's/\.$//' | sed '/^$/d' |
    grep -E '^[a-z0-9-]+(\.[a-z0-9-]+)+$' | sort -u
}

parse_mx_pairs(){
  # Expect dig answer lines; emit host.:prio
  awk 'toupper($4)=="MX" && $5 ~ /^[0-9]+$/ {
         host=tolower($6); sub(/\.$/, "", host); printf "%s.:%s\n", host, $5
       }' |
  grep -E '^[a-z0-9-]+(\.[a-z0-9-]+)+\.:([0-9]+)$' |
  sort -u
}

uniquify_newlines(){
  printf '%s\n' "$1" | sed '/^$/d' | sort -u
}

answer_has_type(){
  local output="$1" type="$2"
  [[ -z "$output" ]] && return 1
  local want
  want=$(printf '%s' "$type" | tr 'a-z' 'A-Z')
  printf '%s\n' "$output" | awk -v want="$want" 'toupper($4)==want {found=1; exit 0} END{exit found?0:1}'
}

join_by_comma(){
  local IFS=','; echo "$*"
}

# ----- global state (per run) -----

declare -a AUTHORITATIVES=()
declare -a DKIM_SELECTORS=()

declare -a AUTH_ROWS=()
DELEG_PARENT_SET=""
DELEG_ZONE_SET=""
DELEG_PARENT_ONLY=""
DELEG_ZONE_ONLY=""
DELEG_OK=0

PARENT_DS_OUTPUT=""
CHILD_DNSKEY_OUTPUT=""

declare -a RESOLVER_ROWS=()

MX_ROWS=""            # newline list of host.:prio
declare -a MX_REPORT_AUTH=()
declare -a MX_REPORT_RECUR=()

SPF_STATUS="${WARN} Not evaluated"
DMARC_STATUS="${WARN} Not evaluated"
SPF_VALUES=""
DMARC_VALUES=""
DKIM_VALUES=""

# ----- dig helpers -----

dig_quiet(){
  # Wrapper to avoid set -e exits: return code propagated; stdout preserved
  dig "$@"
}

dig_answer(){
  dig_quiet "$@" +noall +answer
}

dig_authority(){
  dig_quiet "$@" +noall +authority
}

# ----- discovery routines -----

discover_zone_ns(){
  dig_answer "$DOMAIN" NS | awk '{print $5}' | sanitize_host_list
}

discover_parent_ns(){
  local tld host
  tld="${DOMAIN##*.}"
  host=$(dig +short NS "$tld" | head -n1 | sed 's/\.$//')
  [[ -z "$host" ]] && host="a.nic.${tld}"

  local direct
  direct=$(dig_authority @"$host" "$DOMAIN" NS | awk '$4=="NS"{print $5}')
  direct=$(printf '%s\n' "$direct" | sanitize_host_list)
  if [[ -n "$direct" ]]; then
    printf '%s\n' "$direct"
    return
  fi

  dig +trace "$DOMAIN" NS | awk -v dom="$DOMAIN." '$1==dom && $4=="NS" {print $5}' | sanitize_host_list
}

load_authoritatives(){
  local data
  if [[ -n "$AUTHORITATIVES_OVERRIDE" ]]; then
    data=$(sanitize_host_list "$AUTHORITATIVES_OVERRIDE")
  elif [[ "$AUTO_NS" == "1" ]]; then
    data=$(discover_zone_ns)
    if [[ -z "$data" ]]; then
      data=$(discover_parent_ns)
    fi
  fi

  if [[ -n "$data" ]]; then
    while read -r ns; do
      AUTHORITATIVES+=("$ns")
    done <<< "$data"
  fi
}

load_dkim_selectors(){
  local parsed
  parsed=$(split_list "$DKIM_SELECTORS_RAW")
  if [[ -z "$parsed" ]]; then
    DKIM_SELECTORS=(selector1 selector2)
    return
  fi
  while read -r sel; do
    DKIM_SELECTORS+=("$sel")
  done <<< "$parsed"
}

# ----- data collection -----

collect_authoritative_sections(){
  local ns
  if [[ ${#AUTHORITATIVES[@]} -eq 0 ]]; then
    echo "[info] no authoritative nameservers to query" >&2
    return
  fi

  for ns in "${AUTHORITATIVES[@]}"; do
    local dnskey soa nsrec arec aaaarec mx ans
    local spf_ok=0 dmarc_ok=0 dkim_ok=0
    local spf_txt="" dmarc_txt="" dkim_txt=""

    dnskey=$(dig_answer @"$ns" "$DOMAIN" DNSKEY)
    soa=$(dig_answer @"$ns" "$DOMAIN" SOA)
    nsrec=$(dig_answer @"$ns" "$DOMAIN" NS)
    arec=$(dig_answer @"$ns" "$DOMAIN" A)
    aaaarec=$(dig_answer @"$ns" "$DOMAIN" AAAA)
    mx=$(dig_answer @"$ns" "$DOMAIN" MX)

    local dnskey_ok=0 soa_ok=0 ns_ok=0 a_ok=0 aaaa_ok=0
    [[ -n "$dnskey" ]] && dnskey_ok=1
    [[ -n "$soa" ]] && soa_ok=1
    [[ -n "$nsrec" ]] && ns_ok=1
    answer_has_type "$arec" "A" && a_ok=1
    answer_has_type "$aaaarec" "AAAA" && aaaa_ok=1

    local mx_pairs=""
    if [[ -n "$mx" ]]; then
      mx_pairs=$(printf '%s\n' "$mx" | parse_mx_pairs)
      if [[ -n "$mx_pairs" ]]; then
        MX_ROWS+="$mx_pairs\n"
      fi
    fi

    ans=$(dig_answer @"$ns" "$DOMAIN" TXT)
    if [[ -n "$ans" ]]; then
      local maybe
      maybe=$(printf '%s\n' "$ans" | tr -d '"')
      if printf '%s\n' "$maybe" | grep -qi 'v=spf1'; then
        spf_ok=1
        spf_txt=$(printf '%s\n' "$maybe" | awk 'tolower($0) ~ /v=spf1/ {print}')
      fi
    fi

    ans=$(dig_answer @"$ns" "_dmarc.$DOMAIN" TXT)
    if [[ -n "$ans" ]]; then
      local maybe
      maybe=$(printf '%s\n' "$ans" | tr -d '"')
      if printf '%s\n' "$maybe" | grep -qi 'v=dmarc1'; then
        dmarc_ok=1
        dmarc_txt=$(printf '%s\n' "$maybe" | awk 'tolower($0) ~ /v=dmarc1/ {print}')
      fi
    fi

    local sel
    for sel in "${DKIM_SELECTORS[@]}"; do
      ans=$(dig_answer @"$ns" "${sel}._domainkey.$DOMAIN" TXT)
      if [[ -n "$ans" ]]; then
        local maybe
        maybe=$(printf '%s\n' "$ans" | tr -d '"')
        if printf '%s\n' "$maybe" | grep -Eiq 'v=dkim1|\bp='; then
          dkim_ok=1
          dkim_txt+="$sel: $(printf '%s\n' "$maybe" | awk '{print}')\n"
        fi
      fi
    done

    [[ $spf_ok -eq 1 && -n "$spf_txt" ]] && SPF_VALUES+="$spf_txt\n"
    [[ $dmarc_ok -eq 1 && -n "$dmarc_txt" ]] && DMARC_VALUES+="$dmarc_txt\n"
    [[ $dkim_ok -eq 1 && -n "$dkim_txt" ]] && DKIM_VALUES+="$dkim_txt"

    AUTH_ROWS+=("$ns|$dnskey_ok|$soa_ok|$ns_ok|$a_ok|$aaaa_ok|$( [[ -n $mx_pairs ]] && echo 1 || echo 0 )|$spf_ok|$dmarc_ok|$dkim_ok")
  done
}

collect_delegation(){
  DELEG_PARENT_SET=$(discover_parent_ns)
  DELEG_ZONE_SET=$(discover_zone_ns)

  local tmp1 tmp2
  tmp1=$(mktemp); tmp2=$(mktemp)
  printf '%s\n' "$DELEG_PARENT_SET" >"$tmp1"
  printf '%s\n' "$DELEG_ZONE_SET" >"$tmp2"
  if diff -u "$tmp1" "$tmp2" >/dev/null 2>&1; then
    DELEG_OK=1
  else
    DELEG_OK=0
    DELEG_PARENT_ONLY=$(comm -23 <(sort -u "$tmp1") <(sort -u "$tmp2"))
    DELEG_ZONE_ONLY=$(comm -13 <(sort -u "$tmp1") <(sort -u "$tmp2"))
  fi
  rm -f "$tmp1" "$tmp2"
}

collect_parent_child_dnssec(){
  PARENT_DS_OUTPUT=$(dig +dnssec +noall +answer "$DOMAIN" DS 2>&1)
  CHILD_DNSKEY_OUTPUT=$(dig +dnssec +noall +answer "$DOMAIN" DNSKEY 2>&1)
}

collect_resolvers(){
  local resolver
  for resolver in "${RESOLVERS[@]}"; do
    local ds dk a_ad a_cd
    ds=$(dig_quiet @"$resolver" +dnssec +noall +answer "$DOMAIN" DS)
    dk=$(dig_quiet @"$resolver" +dnssec +noall +answer "$DOMAIN" DNSKEY)
    a_ad=$(dig_quiet @"$resolver" "$DOMAIN" A +adflag +dnssec)
    a_cd=$(dig_quiet @"$resolver" "$DOMAIN" A +cdflag +noall +answer)
    local ad_ok=0 cd_ok=0
    if printf '%s\n' "$a_ad" | grep -q ' flags:.* ad;'; then ad_ok=1; fi
    [[ -n $a_cd ]] && cd_ok=1
    RESOLVER_ROWS+=("$resolver|$( [[ -n $ds ]] && echo 1 || echo 0 )|$( [[ -n $dk ]] && echo 1 || echo 0 )|$ad_ok|$cd_ok")
  done
}

collect_mx_targets(){
  if [[ -z "$MX_ROWS" ]]; then
    return
  fi
  local unique="$(uniquify_newlines "$MX_ROWS")"
  [[ -n "$unique" ]] && MX_ACTUAL_PAIRS="$unique"
  local host prio
  local auth_ns="${AUTHORITATIVES[0]:-}"
  while IFS=':' read -r host prio; do
    [[ -z "$host" || -z "$prio" ]] && continue
    local a_out="" aaaa_out=""
    if [[ -n "$auth_ns" ]]; then
      a_out=$(dig_answer @"$auth_ns" "$host" A)
      aaaa_out=$(dig_answer @"$auth_ns" "$host" AAAA)
    fi
    MX_REPORT_AUTH+=("$host|$( [[ -n $a_out ]] && echo 1 || echo 0 )|$( [[ -n $aaaa_out ]] && echo 1 || echo 0 )")

    local rec_a rec_aaaa
    rec_a=$(dig_answer @"${RESOLVERS[0]}" "$host" A +cdflag)
    rec_aaaa=$(dig_answer @"${RESOLVERS[0]}" "$host" AAAA +cdflag)
    MX_REPORT_RECUR+=("$host|$( [[ -n $rec_a ]] && echo 1 || echo 0 )|$( [[ -n $rec_aaaa ]] && echo 1 || echo 0 )")
  done <<< "$unique"
}

collect_email_txt_summary(){
  if [[ -n "$SPF_VALUES" ]]; then
    SPF_STATUS="${OK} SPF present"
  else
    SPF_STATUS="${BAD} SPF not found"
  fi

  if [[ -n "$DMARC_VALUES" ]]; then
    if printf '%s\n' "$DMARC_VALUES" | grep -qi 'p='; then
      DMARC_STATUS="${OK} DMARC policy present"
    else
      DMARC_STATUS="${WARN} DMARC missing p="
    fi
  else
    DMARC_STATUS="${BAD} DMARC not found"
  fi
}

# ----- reporting -----

emoji_from_flag(){
  [[ $1 -eq 1 ]] && printf '%s' "$OK" || printf '%s' "$NOTSET"
}

status_icon(){
  case "$1" in
    "$OK") echo "$OK";;
    "$BAD") echo "$BAD";;
    "$WARN") echo "$WARN";;
    "$NOTSET") echo "$NOTSET";;
    *) echo "$1";;
  esac
}

pad_text(){
  local text="$1" width="$2"
  printf '%-*s' "$width" "$text"
}

pad_icon(){
  # Subtracting one column keeps emoji alignment closest to the header spacing.
  # Not perfect, but good enough—leave this at "- 1" unless you fully rework the layout.
  local icon="$1" width="$2" display=2 pad
  pad=$(( width - 1 ))
  (( pad < 0 )) && pad=0
  printf '%s%*s' "$icon" "$pad" ""
}

badge_from_status(){
  local status="${1:-}"
  case "$status" in
    "$OK"*) printf '%s' "$OK";;
    "$WARN"*) printf '%s' "$WARN";;
    "$BAD"*) printf '%s' "$BAD";;
    "$NOTSET"*) printf '%s' "$NOTSET";;
    *) printf '%s' "$WARN";;
  esac
}

render_authoritative_table(){
  local widths=(25 10 7 5 5 7 5 6 8 5)
  local headers=("Nameserver" "DNSKEY" "SOA" "NS" "A" "AAAA" "MX" "SPF" "DMARC" "DKIM")

  local line="  "
  local idx
  local last_header=$(( ${#headers[@]} - 1 ))
  for idx in "${!headers[@]}"; do
    line+="$(pad_text "${headers[idx]}" "${widths[idx]}")"
    [[ $idx -ne $last_header ]] && line+="  "
  done
  printf '%s\n' "$line"

  if [[ ${#AUTH_ROWS[@]} -eq 0 ]]; then
    echo "  ${WARN} No authoritative data collected"
    return
  fi

  local row ns dnskey soa nsok a aaaa mx spf dmarc dkim
  for row in "${AUTH_ROWS[@]}"; do
    IFS='|' read -r ns dnskey soa nsok a aaaa mx spf dmarc dkim <<< "$row"

    local cells=()
    cells+=( "$(pad_text "$ns" "${widths[0]}")" )
    cells+=( "$(pad_icon $(status_icon $([[ $dnskey -eq 1 ]] && echo "$OK" || echo "$BAD")) "${widths[1]}")" )
    cells+=( "$(pad_icon $(status_icon $([[ $soa -eq 1 ]] && echo "$OK" || echo "$BAD")) "${widths[2]}")" )
    cells+=( "$(pad_icon $(status_icon $([[ $nsok -eq 1 ]] && echo "$OK" || echo "$BAD")) "${widths[3]}")" )
    cells+=( "$(pad_icon $(status_icon $([[ $a -eq 1 ]] && echo "$OK" || echo "$NOTSET")) "${widths[4]}")" )
    cells+=( "$(pad_icon $(status_icon $([[ $aaaa -eq 1 ]] && echo "$OK" || echo "$NOTSET")) "${widths[5]}")" )
    cells+=( "$(pad_icon $(status_icon $([[ $mx -eq 1 ]] && echo "$OK" || echo "$NOTSET")) "${widths[6]}")" )
    cells+=( "$(pad_icon $(status_icon $([[ $spf -eq 1 ]] && echo "$OK" || echo "$NOTSET")) "${widths[7]}")" )
    cells+=( "$(pad_icon $(status_icon $([[ $dmarc -eq 1 ]] && echo "$OK" || echo "$NOTSET")) "${widths[8]}")" )
    cells+=( "$(pad_icon $(status_icon $([[ $dkim -eq 1 ]] && echo "$OK" || echo "$NOTSET")) "${widths[9]}")" )

    local row_str="  "
    local last_cell=$(( ${#cells[@]} - 1 ))
    for idx in "${!cells[@]}"; do
      row_str+="${cells[idx]}"
      [[ $idx -ne $last_cell ]] && row_str+="  "
    done
    printf '%s\n' "$row_str"
  done
}

render_resolver_table(){
  local widths=(18 7 9 9 9)
  local headers=("Resolver" "DS" "DNSKEY" "A(+ad)" "A(+cd)")

  local line="  "
  local idx
  local last_header=$(( ${#headers[@]} - 1 ))
  for idx in "${!headers[@]}"; do
    line+="$(pad_text "${headers[idx]}" "${widths[idx]}")"
    [[ $idx -ne $last_header ]] && line+="  "
  done
  printf '%s\n' "$line"

  if [[ ${#RESOLVER_ROWS[@]} -eq 0 ]]; then
    echo "  ${WARN} No resolver data collected"
    return
  fi

  local row r ds dk ad cd
  for row in "${RESOLVER_ROWS[@]}"; do
    IFS='|' read -r r ds dk ad cd <<< "$row"

    local cells=()
    cells+=( "$(pad_text "$r" "${widths[0]}")" )
    cells+=( "$(pad_icon $(status_icon $([[ $ds -eq 1 ]] && echo "$OK" || echo "$BAD")) "${widths[1]}")" )
    cells+=( "$(pad_icon $(status_icon $([[ $dk -eq 1 ]] && echo "$OK" || echo "$BAD")) "${widths[2]}")" )
    cells+=( "$(pad_icon $(status_icon $([[ $ad -eq 1 ]] && echo "$OK" || echo "$BAD")) "${widths[3]}")" )
    cells+=( "$(pad_icon $(status_icon $([[ $cd -eq 1 ]] && echo "$OK" || echo "$BAD")) "${widths[4]}")" )

    local row_str="  "
    local last_cell=$(( ${#cells[@]} - 1 ))
    for idx in "${!cells[@]}"; do
      row_str+="${cells[idx]}"
      [[ $idx -ne $last_cell ]] && row_str+="  "
    done
    printf '%s\n' "$row_str"
  done
}

render_mx_targets(){
  if [[ ${#MX_REPORT_AUTH[@]} -eq 0 ]]; then
    echo "  ${WARN} No MX host resolution data"
    return
  fi
  printf "  %-40s  A     AAAA\n" "Host"
  local row host a aaaa
  for row in "${MX_REPORT_AUTH[@]}"; do
    IFS='|' read -r host a aaaa <<< "$row"
    printf "  %-40s  %s     %s\n" "$host" "$(emoji_from_flag $a)" "$(emoji_from_flag $aaaa)"
  done
}

render_mx_targets_recur(){
  if [[ ${#MX_REPORT_RECUR[@]} -eq 0 ]]; then
    echo "  ${WARN} No MX host resolution data"
    return
  fi
  printf "  %-40s  A     AAAA\n" "Host"
  local row host a aaaa
  for row in "${MX_REPORT_RECUR[@]}"; do
    IFS='|' read -r host a aaaa <<< "$row"
    printf "  %-40s  %s     %s\n" "$host" "$(emoji_from_flag $a)" "$(emoji_from_flag $aaaa)"
  done
}

render_email_values(){
  if [[ -n "$SPF_VALUES" ]]; then
    echo "    SPF:"; printf '%s\n' "$SPF_VALUES" | sed 's/^/      - /'
  fi
  if [[ -n "$DMARC_VALUES" ]]; then
    echo "    DMARC:"; printf '%s\n' "$DMARC_VALUES" | sed 's/^/      - /'
  fi
  if [[ -n "$DKIM_VALUES" ]]; then
    echo "    DKIM:"; printf '%s' "$DKIM_VALUES" | sed 's/^/      - /'
  fi
}

render_summary(){
  local deleg_badge="$BAD" dnssec_badge="$BAD" mx_badge="$BAD" spf_badge="$BAD" dmarc_badge="$BAD"
  [[ $DELEG_OK -eq 1 ]] && deleg_badge="$OK"

  local ad_all=1 ad_any=0
  local row ad
  for row in "${RESOLVER_ROWS[@]}"; do
    IFS='|' read -r _ _ _ ad _ <<< "$row"
    if [[ $ad -eq 1 ]]; then
      ad_any=1
    else
      ad_all=0
    fi
  done
  if [[ ${#RESOLVER_ROWS[@]} -gt 0 ]]; then
    if [[ $ad_all -eq 1 ]]; then dnssec_badge="$OK"; elif [[ $ad_any -eq 1 ]]; then dnssec_badge="$WARN"; fi
  fi

  [[ -n "$MX_ACTUAL_PAIRS" ]] && mx_badge="$OK"
  spf_badge="$(badge_from_status "$SPF_STATUS")"
  dmarc_badge="$(badge_from_status "$DMARC_STATUS")"

  printf 'Summary: Delegation %s | DNSSEC(ad) %s | MX %s | SPF %s | DMARC %s\n' \
    "$deleg_badge" "$dnssec_badge" "$mx_badge" "$spf_badge" "$dmarc_badge"
}

report(){
  echo "===================="
  echo "FINAL REPORT"
  echo "===================="

  render_summary

  echo
  echo "• Delegation"
  if [[ -n "$DELEG_PARENT_SET" ]]; then
    echo "  Parent NS:"; printf '%s\n' "$DELEG_PARENT_SET" | sed 's/^/    - /'
  fi
  if [[ -n "$DELEG_ZONE_SET" ]]; then
    echo "  Child NS:"; printf '%s\n' "$DELEG_ZONE_SET" | sed 's/^/    - /'
  fi
  if [[ $DELEG_OK -ne 1 ]]; then
    echo "  ${WARN} Registry NS differ from zone NS"
    if [[ -n "$DELEG_PARENT_ONLY" ]]; then
      echo "  Only at registry:"; printf '%s\n' "$DELEG_PARENT_ONLY" | sed 's/^/    - /'
    fi
    if [[ -n "$DELEG_ZONE_ONLY" ]]; then
      echo "  Only in zone:"; printf '%s\n' "$DELEG_ZONE_ONLY" | sed 's/^/    - /'
    fi
  else
    echo "  ${OK} Delegation aligned"
  fi

  echo
  echo "• Authoritative nameservers"
  render_authoritative_table

  echo
  echo "• Resolver validation"
  render_resolver_table

  echo
  echo "• Email TXT sanity"
  echo "  SPF   : $SPF_STATUS"
  echo "  DMARC : $DMARC_STATUS"

  if [[ -n "$SPF_VALUES$DMARC_VALUES$DKIM_VALUES" ]]; then
    echo
    echo "• Email record values"
    render_email_values
  fi

  echo
  echo "• Parent DS"
  if [[ -n "$PARENT_DS_OUTPUT" ]]; then
    printf '%s\n' "$PARENT_DS_OUTPUT" | sed 's/^/  - /'
  else
    echo "  ${WARN} No DS records returned"
  fi
  echo
  echo "• Child DNSKEY"
  if [[ -n "$CHILD_DNSKEY_OUTPUT" ]]; then
    printf '%s\n' "$CHILD_DNSKEY_OUTPUT" | sed 's/^/  - /'
  else
    echo "  ${WARN} No DNSKEY records returned"
  fi

  echo
  echo "• MX records detected"
  if [[ -n "$MX_ACTUAL_PAIRS" ]]; then
    printf '%s\n' "$MX_ACTUAL_PAIRS" | sed 's/:/ (prio /;s/$/)/;s/^/  - /'
  else
    echo "  ${WARN} None"
  fi

  if [[ ${#MX_REPORT_AUTH[@]} -gt 0 ]]; then
    echo
    echo "• MX target resolution (authoritative)"
    render_mx_targets
    echo
    echo "• MX target resolution (public +cdflag)"
    render_mx_targets_recur
  fi

  echo
  echo "Legend: OK=$OK  WARN=$WARN  FAIL=$BAD  --=$NOTSET"
}

# ----- main routine -----

run_checks(){
  AUTH_ROWS=(); RESOLVER_ROWS=(); MX_REPORT_AUTH=(); MX_REPORT_RECUR=();
  MX_ROWS=""; MX_ACTUAL_PAIRS=""; SPF_VALUES=""; DMARC_VALUES=""; DKIM_VALUES="";
  SPF_STATUS="${WARN} Not evaluated"; DMARC_STATUS="${WARN} Not evaluated";
  DELEG_PARENT_SET=""; DELEG_ZONE_SET=""; DELEG_PARENT_ONLY=""; DELEG_ZONE_ONLY=""; DELEG_OK=0;

  collect_authoritative_sections
  collect_delegation
  collect_parent_child_dnssec
  collect_resolvers
  collect_mx_targets
  collect_email_txt_summary
}

loop_once(){
  printf '\n=== %s | dnssec_health_check v%s ===\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$VERSION"
  run_checks
  report
}

main(){
  require_tool dig

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --domain) DOMAIN="$2"; shift 2;;
      --watch) INTERVAL="$2"; shift 2;;
      --dkim) DKIM_SELECTORS_RAW="$2"; shift 2;;
      --ns)
        AUTHORITATIVES_OVERRIDE="$2"; AUTO_NS=0; shift 2;;
      --auto-ns) AUTO_NS=1; shift;;
      --no-auto-ns) AUTO_NS=0; shift;;
      -h|--help)
        usage_text
        exit 0;;
      --version)
        echo "dnssec_health_check.sh $VERSION"; exit 0;;
      --*)
        printf 'Unknown option: %s\n' "$1" >&2
        usage_text >&2
        exit 1;;
      *)
        if [[ -z "$DOMAIN" ]]; then
          DOMAIN="$1"
          shift
          continue
        else
          printf 'Unexpected argument: %s\n' "$1" >&2
          usage_text >&2
          exit 1
        fi;;
    esac
  done

  [[ -z "$DOMAIN" ]] && die "--domain required (or set DOMAIN env)"

  load_authoritatives
  load_dkim_selectors

  if [[ "$INTERVAL" -gt 0 ]]; then
    while true; do
      loop_once
      echo
      echo "Sleeping ${INTERVAL}s before next pass (Ctrl-C to exit)"
      sleep "$INTERVAL"
    done
  else
    loop_once
  fi
}

usage_text(){
cat <<EOF
dnssec_health_check.sh v$VERSION

Usage: $0 [domain] [--domain name] [--watch SECONDS] [--dkim sel1,sel2] [--auto-ns|--no-auto-ns] [--ns ns1,ns2]

Env vars mirror the flags: DOMAIN, INTERVAL, DKIM_SELECTORS, AUTO_NS, AUTHORITATIVES.
EOF
}

main "$@"
