#!/bin/bash -e

#Parameters to configure
SERVICE_USERNAME=ec2api
SERVICE_PASSWORD=ec2api
SERVICE_TENANT=service
CONNECTION="mysql://ec2api:ec2api@127.0.0.1/ec2api?charset=utf8"
LOG_DIR=/var/log/ec2api
CONF_DIR=/etc/ec2api
SIGNING_DIR=/var/cache/ec2api

#Check for environment
if [[ -z "$OS_AUTH_URL" || -z "$OS_USERNAME" || -z "$OS_PASSWORD" || -z "$OS_TENANT_NAME" ]]; then
    echo "Please set OS_AUTH_URL, OS_USERNAME, OS_PASSWORD and OS_TENANT_NAME"
    exit 1
fi



#### utilities functions merged from devstack to check required parameter is not empty
# Prints line number and "message" in error format
# err $LINENO "message"
function err() {
    local exitcode=$?
    errXTRACE=$(set +o | grep xtrace)
    set +o xtrace
    local msg="[ERROR] ${BASH_SOURCE[2]}:$1 $2"
    echo $msg 1>&2;
    if [[ -n ${SCREEN_LOGDIR} ]]; then
        echo $msg >> "${SCREEN_LOGDIR}/error.log"
    fi
    $errXTRACE
    return $exitcode
}
# Prints backtrace info
# filename:lineno:function
function backtrace {
    local level=$1
    local deep=$((${#BASH_SOURCE[@]} - 1))
    echo "[Call Trace]"
    while [ $level -le $deep ]; do
        echo "${BASH_SOURCE[$deep]}:${BASH_LINENO[$deep-1]}:${FUNCNAME[$deep-1]}"
        deep=$((deep - 1))
    done
}


# Prints line number and "message" then exits
# die $LINENO "message"
function die() {
    local exitcode=$?
    set +o xtrace
    local line=$1; shift
    if [ $exitcode == 0 ]; then
        exitcode=1
    fi
    backtrace 2
    err $line "$*"
    exit $exitcode
}


# Checks an environment variable is not set or has length 0 OR if the
# exit code is non-zero and prints "message" and exits
# NOTE: env-var is the variable name without a '$'
# die_if_not_set $LINENO env-var "message"
function die_if_not_set() {
    local exitcode=$?
    FXTRACE=$(set +o | grep xtrace)
    set +o xtrace
    local line=$1; shift
    local evar=$1; shift
    if ! is_set $evar || [ $exitcode != 0 ]; then
        die $line "$*"
    fi
    $FXTRACE
}

# Test if the named environment variable is set and not zero length
# is_set env-var
function is_set() {
    local var=\$"$1"
    eval "[ -n \"$var\" ]" # For ex.: sh -c "[ -n \"$var\" ]" would be better, but several exercises depends on this
}

#######################################

get_data() {
    local match_column=$(($1 + 1))
    local regex="$2"
    local output_column=$(($3 + 1))
    shift 3

    output=$("$@" | \
           awk -F'|' \
               "! /^\+/ && \$${match_column} ~ \"^ *${regex} *\$\" \
                { print \$${output_column} }")

    echo "$output"
}

get_id () {
    get_data 1 id 2 "$@"
}

get_user() {
    local username=$1

    local user_id=$(get_data 2 $username 1 keystone user-list)

    if [ -n "$user_id" ]; then
        echo "Found existing $username user" >&2
        echo $user_id
    else
        echo "Creating $username user..." >&2
        get_id keystone user-create --name=$username \
                                    --pass="$SERVICE_PASSWORD" \
                                    --tenant $SERVICE_TENANT \
                                    --email=$username@example.com
    fi
}

add_role() {
    local user_id=$1
    local tenant=$2
    local role_id=$3
    local username=$4

    user_roles=$(keystone user-role-list \
                          --user_id $user_id\
                          --tenant $tenant 2>/dev/null)
    die_if_not_set $LINENO user_roles "Fail to get user_roles for tenant($tenant) and user_id($user_id)"
    existing_role=$(get_data 1 $role_id 1 echo "$user_roles")
    if [ -n "$existing_role" ]
    then
        echo "User $username already has role $role_id" >&2
        return
    fi
    keystone user-role-add --tenant $tenant \
             --user_id $user_id \
             --role_id $role_id
}


# Determines if the given option is present in the INI file
# ini_has_option config-file section option
function ini_has_option() {
    local file=$1
    local section=$2
    local option=$3
    local line
    line=$(sudo sed -ne "/^\[$section\]/,/^\[.*\]/ { /^$option[ \t]*=/ p; }" "$file")
    [ -n "$line" ]
}

# Set an option in an INI file
# iniset config-file section option value
function iniset() {
    local file=$1
    local section=$2
    local option=$3
    local value=$4
    if ! sudo grep -q "^\[$section\]" "$file"; then
        # Add section at the end
        sudo bash -c "echo -e \"\n[$section]\" >>\"$file\""
    fi
    if ! ini_has_option "$file" "$section" "$option"; then
        # Add it
        sudo sed -i -e "/^\[$section\]/ a\\
$option = $value
" "$file"
    else
        # Replace it
        sudo sed -i -e "/^\[$section\]/,/^\[.*\]/ s|^\($option[ \t]*=[ \t]*\).*$|\1$value|" "$file"
    fi
}


#create keystone user with admin privileges
ADMIN_ROLE=$(get_data 2 admin 1 keystone role-list)
die_if_not_set $LINENO ADMIN_ROLE "Fail to get ADMIN_ROLE by 'keystone role-list' "
SERVICE_TENANT_ID=$(get_data 2 service 1 keystone tenant-list)
die_if_not_set $LINENO SERVICE_TENANT_ID "Fail to get service tenant 'keystone tenant-list' "

echo ADMIN_ROLE $ADMIN_ROLE
echo SERVICE_TENANT $SERVICE_TENANT

SERVICE_USERID=$(get_user $SERVICE_USERNAME)
die_if_not_set $LINENO SERVICE_USERID "Fail to get user for $SERVICE_USERNAME"
echo SERVICE_USERID $SERVICE_USERID
add_role $SERVICE_USERID $SERVICE_TENANT $ADMIN_ROLE $SERVICE_USERNAME

#create log dir
echo Creating log dir
sudo install -d $LOG_DIR

CONF_FILE=$CONF_DIR/ec2api.conf
APIPASTE_FILE=$CONF_DIR/api-paste.ini
#copy conf files (do not override it)
echo Creating configs
sudo mkdir -p /etc/ec2api > /dev/null
if [ ! -s $CONF_FILE ]; then
    sudo cp etc/ec2api/ec2api.conf.sample $CONF_FILE
fi
if [ ! -s $APIPASTE_FILE ]; then
    sudo cp etc/ec2api/api-paste.ini $APIPASTE_FILE
fi

AUTH_HOST=${OS_AUTH_URL#*//}
AUTH_HOST=${AUTH_HOST%:*}
AUTH_CACHE_DIR=${AUTH_CACHE_DIR:-/var/cache/ec2api}
AUTH_PORT=`keystone catalog|grep -A 9 identity|grep adminURL|awk '{print $4}'`
AUTH_PORT=${AUTH_PORT##*:}
AUTH_PORT=${AUTH_PORT%%/*}
AUTH_PROTO=${OS_AUTH_URL%%:*}
PUBLIC_URL=${OS_AUTH_URL%:*}:8788/

#update default config with some values
iniset $CONF_FILE DEFAULT api_paste_config $APIPASTE_FILE
iniset $CONF_FILE DEFAULT logging_context_format_string "%(asctime)s.%(msecs)03d %(levelname)s %(name)s [%(request_id)s %(user_name)s %(project_name)s] %(instance)s%(message)s"
iniset $CONF_FILE DEFAULT verbose True
iniset $CONF_FILE DEFAULT keystone_url "$OS_AUTH_URL"
iniset $CONF_FILE database connection "$CONNECTION"

iniset $CONF_FILE keystone_authtoken signing_dir $SIGNING_DIR
iniset $CONF_FILE keystone_authtoken auth_host $AUTH_HOST
iniset $CONF_FILE keystone_authtoken admin_user $SERVICE_USERNAME
iniset $CONF_FILE keystone_authtoken admin_password $SERVICE_PASSWORD
iniset $CONF_FILE keystone_authtoken admin_tenant_name $SERVICE_TENANT
iniset $CONF_FILE keystone_authtoken auth_protocol $AUTH_PROTO
iniset $CONF_FILE keystone_authtoken auth_port $AUTH_PORT


#init cache dir
echo Creating signing dir
sudo mkdir -p $AUTH_CACHE_DIR
sudo chown $USER $AUTH_CACHE_DIR
sudo rm -f $AUTH_CACHE_DIR/*

#install it
echo Installing package
sudo python setup.py develop
sudo rm -rf build ec2_api.egg-info

#recreate database
echo Setuping database
sudo bin/ec2api-db-setup deb
