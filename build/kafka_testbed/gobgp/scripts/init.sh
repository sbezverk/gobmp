#!/bin/sh

# log level
loglevel="$LOG_LEVEL"
# Sleep time until next run
pause_time="$VAR_SLEEP"
# config file template path
template="/etc/gobgp/gobgp.tmpl"
# config file path
configuration="/etc/gobgp/gobgp.conf"
# GRPC port
grpc_port="$VAR_GRPC_PORT"

# TRAPS
trap "log_warn \"Got signal SIGINIT,exiting..\" && exit 1" SIGINT
trap "log_warn \"Got signal SIGTERM,exiting..\" && exit 1" SIGTERM

if [ -z ${loglevel} ]; then
    loglevel='INFO'
elif [ ${loglevel} == "verbose" ] || [ ${loglevel} == "very-verbose" ]; then
    loglevel='DEBUG'
fi

log_debug() {
    if echo "${loglevel}" | grep "^DEBUG" >/dev/null; then
        log "\"level\":\"debug\",\"msg\":\"${1}\""
    fi
}

log_info() {
    if echo "${loglevel}" | grep -e "^DEBUG" -e "^INFO" >/dev/null; then
        log "\"level\":\"info\",\"msg\":\"${1}\""
    fi
}

log_warn() {
    if echo "${loglevel}" | grep -e "^DEBUG" -e "^INFO" -e "^WARN" >/dev/null; then
        log "\"level\":\"warn\",\"msg\":\"${1}\""
    fi
}

log_error() {
    if echo "${loglevel}" | grep -e "^DEBUG" -e "^INFO" -e "^WARN" -e "^ERROR" >/dev/null; then
        log "\"level\":\"error\",\"msg\":\"${1}\""
    fi
}

log() {
    echo "{\"key\":\"${0}\",${1},\"time\":\"$(date '+%Y-%m-%dT%H:%M:%S%z')\"}"
}

export VAR_CONTAINER_IP=$(ip a | grep "$(ip r | grep default | head -n1 | awk '{print $5}')" | grep inet | head -n1 | awk '{print $2}' | sed 's/\/.*//g')
log_debug "container_ip=$VAR_CONTAINER_IP"

initialize() {
    # Check and set default loop pause
    if [[ "$(printf '%s' "$VAR_SLEEP")" == '' ]]; then
        log_debug 'Variable [VAR_SLEEP] is not set'
        log_debug "Set to default: 10 seconds"
        pause_time='10'
    else
        log_debug "variable [VAR_SLEEP] found.Value:${pause_time}"
    fi

    # Check that template configuration file exists
    if [[ ! -f "${template}" ]]; then
        log_error "Configuration template ${template} is missing.Exiting."
        exit 1
    fi
}

# ip validation [ipcalc must be installed]
checkip() {
    if ipcalc -ns "${1}" >/dev/null; then
        return 0
    else
        return 1
    fi
}

# port validation
checkport() {
    port=${1}
    reg='^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$'
    if [[ ${port} =~ ^${reg} ]]; then
        # Return 0 in valid port
        return 0
    fi
    # return non-zero for not valid ports
    return 1
}

# gobgp configuration file creation and update
check_and_fix() {
    # Get the list of vars from template
    vars=$(grep -E 'VAR_[A-Z]+_?[A-Z]+_?[0-9]?' ${template} -o | sort | uniq | xargs)

    # Create a temporary configuration file
    #log "Creating a new temporary configuration file ${configuration}.temp .."
    cat ${template} >"${configuration}.temp"

    # Check that all variables are not empty and update them in configuration temp file
    for var in ${vars}; do
        tmp="\$${var}"
        evaltmp=$(eval "echo ${tmp}")
        if [[ -z ${evaltmp} ]]; then
            log_error "Required variable ${var} is not set.Exiting."
            exit 1
        fi
        # Check if var expands in ip or hostname
        checkip "${evaltmp}"
        if [[ $? == 0 ]]; then
            sed -i "s/${var}/${evaltmp}/" "${configuration}.temp" >/dev/null
        else
            ip=$(dig +short +search ${evaltmp})
            # Update only when dns resolving service ip
            if [[ "$(printf '%s' "${ip}")" != '' ]]; then
                sed -i "s/${var}/${ip}/" "${configuration}.temp" >/dev/null
            fi
        fi
    done

    diff ${configuration} ${configuration}.temp >/dev/null 2>/dev/null
    if [[ ${?} != 0 ]]; then
        if [[ ! -f "${configuration}" ]]; then
            bef_changes="$(diff -wba ${template} ${configuration}.temp | grep -e '^- ' | sed 's/^-/"/g' | sed 's/ = /":/g' | sed 's/ *//g' | sed ':a;N;$!ba;s/\n/,/g' 2>/dev/null)"
            af_changes="$(diff -wba ${template} ${configuration}.temp | grep -e '^+ ' | sed 's/^+/"/g' | sed 's/ = /":/g' | sed 's/ *//g' | sed ':a;N;$!ba;s/\n/,/g' 2>/dev/null)"
        else
            bef_changes="$(diff -wba ${configuration} ${configuration}.temp | grep -e '^- ' | sed 's/^-/"/g' | sed 's/ = /":/g' | sed 's/ *//g' | sed ':a;N;$!ba;s/\n/,/g' 2>/dev/null)"
            af_changes="$(diff -wba ${configuration} ${configuration}.temp | grep -e '^+ ' | sed 's/^+/"/g' | sed 's/ = /":/g' | sed 's/ *//g' | sed ':a;N;$!ba;s/\n/,/g' 2>/dev/null)"
        fi
        log_info "Updating configuration file ${configuration}"
        log_info "{\"values_before\":{${bef_changes}}}"
        log_info "{\"values_after\":{${af_changes}}}"
        mv -f "${configuration}.temp" ${configuration}
        return 1
    fi
    log_debug "Configuration drift not detected"
    log_debug "Removing temporary file ${configuration}.temp"
    rm -f "${configuration}.temp" >/dev/null
    return 0
}

# Reload gobgpd when there's a pid or calls start_gobgpd if isn't.
reload_bgpd() {
    gobgppid="$(pidof gobgpd)"
    if [[ "$(printf '%s' "${gobgppid}")" == '' ]]; then
        log_warn "Process gobgpd not found.Starting gobgpd"
        start_gobgpd
        return
    fi
    log_info "Reloading gobpgd configuration"
    kill -HUP "${gobgppid}"
    ret=$?
    if [[ ${ret} == 0 ]]; then
        log_info "Reload signal successful"
    else
        log_warn "Reload signal failed"
    fi
}

start_gobgpd() {
    if pidof gobgpd >/dev/null; then
        log_warn "Process gobgpd is already running"
        return
    fi
    opts=''
    if [[ "$(printf '%s' "${grpc_port}")" != "" ]] && checkport ${grpc_port}; then
        opts="--api-hosts \"0.0.0.0:${grpc_port}\""
    fi
    if [[ "${loglevel}" == "DEBUG" ]]; then
        opts="${opts} --log-level=debug"
    fi
    log_info "Starting gobgpd using opts: ${opts}"
    gobgpd -f ${configuration} ${opts} &
}

main() {
    log_info "${0} Start"
    initialize
    while true; do
        check_and_fix
        status=$?
        if [[ ${status} == 1 ]]; then
            reload_bgpd
        fi
        start_gobgpd
        log_debug "Pause for ${pause_time} seconds"
        sleep ${pause_time}
    done
    wait
    log_info "${0} Exit"
}

main
exit $?