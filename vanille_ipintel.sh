#!/bin/bash
#===========================================================
#   NODE SPECTRE / VANILLE SYSTEMS
#   Module: IP Intelligence v1.3 (ASN auto-lookup + VPN/Proxy)
#===========================================================
# Reqs: curl, jq
# Optional: export VPN_API_PROVIDER="vpnapi" and VPN_API_KEY="your_key"
#   Supported providers (optional): vpnapi (vpnapi.io), ipqs (ipqualityscore)
#===========================================================
# probado por mi novio unai sin su consentimiento 🫦
LOG_DIR="$HOME/.config/nodespectre/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/iptrace_$(date +%Y-%m-%d).log"

green="\033[1;32m"; white="\033[1;37m"; grey="\033[90m"
cyan="\033[1;36m"; yellow="\033[1;33m"; red="\033[1;31m"; reset="\033[0m"

banner() {
  clear
  echo -e "${green}
╔═══════════════════════════════════════════╗
║          NODE SPECTRE  INTELLIGENCE       ║
║             Vanille Systems 2025          ║
╚═══════════════════════════════════════════╝${reset}"
  echo -e "${grey}『 Network OSINT module — IP & ASN + VPN/Proxy detection 』${reset}\n"
}

log_data() { echo "[$(date '+%H:%M:%S')] $1" >> "$LOG_FILE"; }
_jq() { echo "$1" | jq -r "$2" 2>/dev/null || true; }

# --- Heuristics list: cloud / vpn / hoster keywords (case-insensitive) ---
CLOUD_KEYWORDS=("amazon" "aws" "google" "microsoft" "azure" "digitalocean" "linode" "vultr" "ovh" "hetzner" "cloudflare" "akama i" "oracle" "alibaba" "tencent" "scaleway" "contabo" "hosting" "rackspace" "softlayer" "transip" "huawei" "fastly" "edgecast" "proxy" "vpn" "tor" "anonymizer" "ipvanish" "nordvpn" "expressvpn" "privateinternetaccess" "m247" "hostinger")

# Query optional dedicated VPN/proxy detection providers (if API key provided)
check_with_vpn_provider() {
  local ip="$1"
  if [[ -z "$VPN_API_PROVIDER" || -z "$VPN_API_KEY" ]]; then
    return 1
  fi

  case "${VPN_API_PROVIDER,,}" in
    vpnapi)
      # vpnapi.io (example): https://vpnapi.io/api/<IP>?key=<KEY>
      resp=$(curl -s "https://vpnapi.io/api/${ip}?key=${VPN_API_KEY}")
      if [[ -n "$resp" ]]; then
        is_vpn=$(_jq "$resp" '.security.is_vpn // false')
        is_proxy=$(_jq "$resp" '.security.is_proxy // false')
        is_tor=$(_jq "$resp" '.security.is_tor // false')
        risk_score=$(_jq "$resp" '.security.score // 0')
        echo "$is_vpn|$is_proxy|$is_tor|$risk_score|provider:vpnapi"
        return 0
      fi
      ;;
    ipqs|ipqualityscore)
      # IPQualityScore: https://www.ipqualityscore.com/documentation/proxy-detection/overview
      resp=$(curl -s "https://ipqualityscore.com/api/json/ip/${VPN_API_KEY}/${ip}")
      if [[ -n "$resp" ]]; then
        is_vpn=$(_jq "$resp" '.vpn // false')
        is_proxy=$(_jq "$resp" '.proxy // false')
        is_tor=$(_jq "$resp" '.tor // false')
        risk_score=$(_jq "$resp" '.fraud_score // 0')
        echo "$is_vpn|$is_proxy|$is_tor|$risk_score|provider:ipqs"
        return 0
      fi
      ;;
    *)
      return 1
      ;;
  esac
  return 1
}

# Heuristic: check ISP / ASN strings for cloud/vpn keywords
heuristic_cloud_check() {
  local haystack="${1,,}"
  for kw in "${CLOUD_KEYWORDS[@]}"; do
    if [[ "$haystack" == *"$kw"* ]]; then
      echo "true|$kw"
      return 0
    fi
  done
  echo "false|none"
  return 0
}

get_asn_details() {
  local asn_raw=$1
  local asn_num="${asn_raw^^}"
  asn_num="${asn_num/AS/}"
  if [[ -z "$asn_num" || "$asn_num" == "null" ]]; then
    echo -e "${yellow}No ASN found for this IP.${reset}\n"
    return 1
  fi
  log_data "Lookup ASN AS${asn_num}"
  local bgp=$(curl -s "https://api.bgpview.io/asn/${asn_num}")
  local name=$(_jq "$bgp" '.data.name // "N/A"')
  local country=$(_jq "$bgp" '.data.country_code // "N/A"')
  local desc=$(_jq "$bgp" '.data.description // "N/A"')
  local prefixes=$(_jq "$bgp" '.data.ipv4_prefixes | length // 0')
  local peers=$(_jq "$bgp" '.data.peers | length // 0')
  local rir=$(_jq "$bgp" '.data.rir_allocation.rir_name // "N/A"')
  local date_alloc=$(_jq "$bgp" '.data.rir_allocation.allocation_date // "N/A"')

  echo -e "${white}ASN Name:${reset} $name"
  echo -e "${white}ASN Country:${reset} $country"
  echo -e "${white}ASN Desc:${reset} $desc"
  echo -e "${white}IPv4 Prefixes:${reset} $prefixes"
  echo -e "${white}Peers:${reset} $peers"
  echo -e "${white}RIR:${reset} $rir"
  echo -e "${white}Allocation Date:${reset} $date_alloc"
  echo -e "${grey}https://bgpview.io/asn/${asn_num}${reset}\n"
  log_data "ASN AS${asn_num} -> $name ($country)"
  echo "$name|$country|$desc|$prefixes|$peers|$rir|$date_alloc"
  return 0
}

# Main IP info + VPN/proxy detection
get_ip_info() {
  local ip="$1"
  if [ -z "$ip" ]; then
    ip=$(curl -s https://ipinfo.io/ip 2>/dev/null)
    ip="${ip//[$'\t\r\n ']}"
  fi
  if [ -z "$ip" ]; then
    echo -e "${yellow}No IP detected and no input provided.${reset}"
    return 1
  fi

  echo -e "${cyan}\nTracing IP → ${white}$ip${reset}\n"
  log_data "Scanning $ip"

  ipapi=$(curl -s "https://ipapi.co/${ip}/json/")
  ipapicomm=$(curl -s "http://ip-api.com/json/${ip}")
  ipinfo=$(curl -s "https://ipinfo.io/${ip}/json")

  city=$(_jq "$ipapi" '.city // "N/A"')
  region=$(_jq "$ipapi" '.region // "N/A"')
  country=$(_jq "$ipapi" '.country_name // "N/A"')
  org=$(_jq "$ipapi" '.org // "N/A"')
  asn=$(_jq "$ipapi" '.asn // "N/A"')
  lat=$(_jq "$ipapicomm" '.lat // "0"')
  lon=$(_jq "$ipapicomm" '.lon // "0"')
  tz=$(_jq "$ipapicomm" '.timezone // "N/A"')
  zip=$(_jq "$ipapicomm" '.zip // "N/A"')
  # ip-api has "hosting" sometimes
  hosting_flag=$(_jq "$ipapicomm" '.hosting // "false"')
  # ipapi may have a privacy block (vpn/proxy) depending on account level
  privacy_proxy=$(_jq "$ipapi" '.privacy.proxy // null')
  privacy_vpn=$(_jq "$ipapi" '.privacy.vpn // null')
  ipinfo_org=$(_jq "$ipinfo" '.org // "N/A"')
  ipinfo_bogon=$(_jq "$ipinfo" '.bogon // false')

  echo -e "${white}IP Address:${reset} $ip"
  echo -e "${white}City:${reset} $city"
  echo -e "${white}Region:${reset} $region"
  echo -e "${white}Country:${reset} $country"
  echo -e "${white}ISP (ipapi):${reset} $org"
  echo -e "${white}ISP (ipinfo):${reset} $ipinfo_org"
  echo -e "${white}ASN:${reset} $asn"
  echo -e "${white}Coordinates:${reset} $lat,$lon"
  echo -e "${white}Timezone:${reset} $tz"
  echo -e "${white}Postal:${reset} $zip\n"

  log_data "Result for $ip — $city, $country, ASN $asn ($org)"

  # Gather provider-vetted check (optional)
  provider_result=$(check_with_vpn_provider "$ip" 2>/dev/null || true)
  # Heuristics on ASN/ISP strings
  isp_combo="${org} ${ipinfo_org} ${asn}"
  hc=$(heuristic_cloud_check "$isp_combo")
  hc_flag=$(echo "$hc" | cut -d'|' -f1)
  hc_kw=$(echo "$hc" | cut -d'|' -f2)

  # Consolidate signals into a risk score
  score=0
  reasons=()

  # ip-api hosting
  if [[ "$hosting_flag" == "true" ]]; then
    ((score+=30)); reasons+=("hosting_flag(ip-api)")
  fi

  # ipapi privacy flags (if present)
  if [[ "$privacy_proxy" == "true" || "$privacy_vpn" == "true" ]]; then
    ((score+=40)); reasons+=("privacy_flags(ipapi)")
  fi

  # ipinfo bogon (reserved)
  if [[ "$ipinfo_bogon" == "true" ]]; then
    ((score+=50)); reasons+=("bogon(ipinfo)")
  fi

  # ASN/ISP heuristic
  if [[ "$hc_flag" == "true" ]]; then
    ((score+=30)); reasons+=("isp_asn_keyword:$hc_kw")
  fi

  # provider result (if any)
  if [[ -n "$provider_result" ]]; then
    p_vpn=$(echo "$provider_result" | cut -d'|' -f1)
    p_proxy=$(echo "$provider_result" | cut -d'|' -f2)
    p_tor=$(echo "$provider_result" | cut -d'|' -f3)
    p_score=$(echo "$provider_result" | cut -d'|' -f4)
    p_tag=$(echo "$provider_result" | cut -d'|' -f5)
    [[ "$p_vpn" == "true" ]] && ((score+=50)) && reasons+=("vpn_provider")
    [[ "$p_proxy" == "true" ]] && ((score+=50)) && reasons+=("proxy_provider")
    [[ "$p_tor" == "true" ]] && ((score+=40)) && reasons+=("tor_provider")
    # include vendor numeric score (normalized small)
    if [[ "$p_score" =~ ^[0-9]+$ ]]; then
      ((score+= (p_score/5) ))
      reasons+=("$p_tag:score($p_score)")
    fi
  fi

  # clamp score
  if (( score < 0 )); then score=0; fi
  if (( score > 100 )); then score=100; fi

  # Decide label
  label="clean"
  if (( score >= 80 )); then label="hosting/vpn (very likely)"
  elif (( score >= 50 )); then label="suspicious (possible vpn/proxy/host)"
  elif (( score > 20 )); then label="maybe-hosting (cloud provider)"
  else label="clean"
  fi

  # Print detection summary
  echo -e "${cyan}VPN/Proxy detection summary:${reset}"
  echo -e "  ${white}Score:${reset} ${score}/100"
  echo -e "  ${white}Label:${reset} ${red}$label${reset}"
  if [ ${#reasons[@]} -gt 0 ]; then
    echo -e "  ${white}Signals:${reset} ${reasons[*]}"
  fi
  if [[ -n "$provider_result" ]]; then
    echo -e "  ${white}Provider result:${reset} $provider_result"
  fi
  echo -e "\n"

  # If ASN present, show details (returns a string, we printed earlier)
  if [[ -n "$asn" && "$asn" != "null" && "$asn" != "N/A" ]]; then
    asn_token=$(echo "$asn" | grep -o -E "AS[0-9]+|[0-9]{3,}" | head -n1 || true)
    if [[ -n "$asn_token" ]]; then
      get_asn_details "$asn_token" >/dev/null 2>&1 || true
    fi
  fi

  log_data "Detection: $label score:$score reasons:${reasons[*]}"
  return 0
}

export_report() {
  local ip="$1"
  if [ -z "$ip" ]; then
    read -p "Enter IP to export report for: " ip
  fi
  local export_file="$LOG_DIR/export_${ip}_$(date +%H-%M-%S).txt"
  {
    echo "IP Intelligence report — $(date)"
    echo "----------------------------------------"
    get_ip_info "$ip"
  } > "$export_file"
  echo -e "${green}Report saved to:${reset} $export_file\n"
  log_data "Exported report for $ip → $export_file"
}

menu() {
  banner
  echo -e "${cyan}[1]${reset} My IP"
  echo -e "${cyan}[2]${reset} Track IP (enter any IP)"
  echo -e "${cyan}[3]${reset} Export report (IP -> txt)"
  echo -e "${cyan}[0]${reset} Exit\n"
  read -p "$(echo -e "${green}>>${reset} Select: ")" option

  case $option in
    1) get_ip_info ""; read -p $'\nPress enter to return...'; menu ;;
    2) read -p "Enter IP: " ip; get_ip_info "$ip"; read -p $'\nPress enter to return...'; menu ;;
    3) read -p "Enter IP (or blank to prompt): " ip; export_report "$ip"; read -p $'\nPress enter to return...'; menu ;;
    0) clear; exit 0 ;;
    *) echo -e "${yellow}Invalid option${reset}"; sleep 1; menu ;;
  esac
}

if ! command -v jq >/dev/null 2>&1; then
  echo -e "${yellow}This script requires 'jq'. Install it first (apt install jq).${reset}"
  exit 1
fi

# Example: to enable provider checks export:
# export VPN_API_PROVIDER="vpnapi"
# export VPN_API_KEY="your_api_key_here"
menu
