#!/bin/bash -e

#Parameters to configure
SERVICE_USERNAME=ec2api
SERVICE_PASSWORD=ec2api
SERVICE_TENANT=service
# this domain name will be used for project and user
SERVICE_DOMAIN_NAME=Default
EC2API_PORT=8788
CONNECTION="mysql://ec2api:ec2api@127.0.0.1/ec2api?charset=utf8"
LOG_DIR=/var/log/ec2api
CONF_DIR=/etc/ec2api
NOVA_CONF=/etc/nova/nova.conf
CONF_FILE=$CONF_DIR/ec2api.conf
APIPASTE_FILE=$CONF_DIR/api-paste.ini

DATA_DIR=${DATA_DIR:-/var/lib/ec2api}
AUTH_CACHE_DIR=${AUTH_CACHE_DIR:-/var/cache/ec2api}

#Check for environment
if [[ -z "$OS_AUTH_URL" || -z "$OS_USERNAME" || -z "$OS_PASSWORD" ]]; then
    echo "Please set OS_AUTH_URL, OS_USERNAME, OS_PASSWORD"
    exit 1
fi
if [[ -z "$OS_TENANT_NAME" && -z "$OS_PROJECT_NAME" ]]; then
    echo "Please set OS_TENANT_NAME or OS_PROJECT_NAME"
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

    local user_id=$(openstack user show $username -f value -c id 2>/dev/null)

    if [ -n "$user_id" ]; then
        echo "Found existing $username user" >&2
        echo $user_id
    else
        echo "Creating $username user..." >&2
        openstack user create -f value -c id \
                              $username \
                              --password "$SERVICE_PASSWORD" \
                              --project $SERVICE_TENANT \
                              --email $username@example.com
    fi
}

add_role() {
    local user_id=$1
    local tenant=$2
    local role_id=$3
    local username=$4
    local domain=$5

    if [[ -n $domain ]]
    then
        domain_args="--project-domain $domain --user-domain $domain"
    fi

    # Gets user role id
    existing_role=$(openstack role assignment list -f value -c User \
        --role $role_id \
        --user $user_id \
        --project $tenant \
        $domain_args)
    if [ -n "$existing_role" ]
    then
        echo "User $username already has role $role_id" >&2
        return
    fi

    # Adds role to user
    openstack role add $role_id \
                       --user $user_id \
                       --project $tenant \
                       $domain_args
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

# Get an option from an INI file
# iniget config-file section option
function iniget() {
    local file=$1
    local section=$2
    local option=$3
    local line
    line=$(sed -ne "/^\[$section\]/,/^\[.*\]/ { /^$option[ \t]*=/ p; }" "$file")
    echo ${line#*=}
}

# Copy an option from Nova INI file or from environment if it's set
function copynovaopt() {
    local option_name=$1
    local option_group=$2
    local env_var
    local option
    env_var=${option_name^^}
    if [ ${!env_var+x} ]; then
        option=${!env_var}
    elif ini_has_option "$NOVA_CONF" $option_group $option_name; then
        option=$(iniget $NOVA_CONF $option_group $option_name)
    else
        return 0
    fi
    iniset $CONF_FILE $option_group $option_name $option
}

if [[ -n $(openstack catalog show network) ]]; then
    VPC_SUPPORT="True"
    DISABLE_EC2_CLASSIC="True"
else
    VPC_SUPPORT="False"
    DISABLE_EC2_CLASSIC="False"
fi
if [[ "$VPC_SUPPORT" == "True" && -z "$EXTERNAL_NETWORK" ]]; then
    declare -a neutron_output
    readarray -s 3 -t neutron_output < <(openstack network list --external)
    if ((${#neutron_output[@]} < 2)); then
        reason="No external network is declared in Neutron."
    elif ((${#neutron_output[@]} > 2)); then
        reason="More than one external networks are declared in Neutron."
    else
        EXTERNAL_NETWORK=$(echo $neutron_output | awk -F '|' '{ print $3 }')
    fi
    die_if_not_set $LINENO EXTERNAL_NETWORK "$reason. Please set EXTERNAL_NETWORK environment variable to the external network dedicated to EC2 elastic IP operations"
fi

#create keystone user with admin and service privileges
ADMIN_ROLE=$(openstack role show admin -c id -f value)
die_if_not_set $LINENO ADMIN_ROLE "Fail to get ADMIN_ROLE by 'openstack role show' "
SERVICE_ROLE=$(openstack role show service -c id -f value)
die_if_not_set $LINENO ADMIN_ROLE "Fail to get SERVICE_ROLE by 'openstack role show' "
SERVICE_TENANT_ID=$(openstack project show service -c id -f value)
die_if_not_set $LINENO SERVICE_TENANT_ID "Fail to get service tenant 'openstack project show' "

echo ADMIN_ROLE $ADMIN_ROLE
echo SERVICE_ROLE $SERVICE_ROLE
echo SERVICE_TENANT $SERVICE_TENANT

SERVICE_USERID=$(get_user $SERVICE_USERNAME)
die_if_not_set $LINENO SERVICE_USERID "Fail to get user for $SERVICE_USERNAME"
echo SERVICE_USERID $SERVICE_USERID
SERVICE_DOMAIN_NAME=${SERVICE_DOMAIN_NAME:-Default}
add_role $SERVICE_USERID $SERVICE_TENANT $ADMIN_ROLE $SERVICE_USERNAME
add_role $SERVICE_USERID $SERVICE_TENANT $SERVICE_ROLE $SERVICE_USERNAME $SERVICE_DOMAIN_NAME

#create log dir
echo Creating log dir
sudo install -d $LOG_DIR --owner=$USER

#copy conf files (do not override it)
echo Creating configs
sudo mkdir -p /etc/ec2api > /dev/null
if [ ! -s $CONF_FILE ]; then
    sudo touch $CONF_FILE
fi
if [ ! -s $APIPASTE_FILE ]; then
    sudo cp etc/ec2api/api-paste.ini $APIPASTE_FILE
fi


#update default config with some values
iniset $CONF_FILE DEFAULT ec2api_listen_port "$EC2API_PORT"
iniset $CONF_FILE DEFAULT ec2_port "$EC2API_PORT"
iniset $CONF_FILE DEFAULT api_paste_config $APIPASTE_FILE
iniset $CONF_FILE DEFAULT logging_context_format_string "%(asctime)s.%(msecs)03d %(levelname)s %(name)s [%(request_id)s %(user_name)s %(project_name)s] %(instance)s%(message)s"
iniset $CONF_FILE DEFAULT log_dir "$LOG_DIR"
iniset $CONF_FILE DEFAULT verbose True
iniset $CONF_FILE DEFAULT keystone_ec2_tokens_url "$OS_AUTH_URL/v3/ec2tokens"
iniset $CONF_FILE database connection "$CONNECTION"
iniset $CONF_FILE DEFAULT disable_ec2_classic "$DISABLE_EC2_CLASSIC"
iniset $CONF_FILE DEFAULT external_network "$EXTERNAL_NETWORK"
iniset $CONF_FILE oslo_concurrency lock_path "$EC2API_STATE_PATH"
iniset $CONF_FILE DEFAULT state_path "$DATA_DIR"

GROUP_AUTHTOKEN="keystone_authtoken"
iniset $CONF_FILE $GROUP_AUTHTOKEN signing_dir "$AUTH_CACHE_DIR"
iniset $CONF_FILE $GROUP_AUTHTOKEN www_authenticate_uri "$OS_AUTH_URL"
iniset $CONF_FILE $GROUP_AUTHTOKEN auth_url "$OS_AUTH_URL"
iniset $CONF_FILE $GROUP_AUTHTOKEN username $SERVICE_USERNAME
iniset $CONF_FILE $GROUP_AUTHTOKEN password $SERVICE_PASSWORD
iniset $CONF_FILE $GROUP_AUTHTOKEN project_name $SERVICE_TENANT
iniset $CONF_FILE $GROUP_AUTHTOKEN project_domain_name $SERVICE_DOMAIN_NAME
iniset $CONF_FILE $GROUP_AUTHTOKEN user_domain_name $SERVICE_DOMAIN_NAME
iniset $CONF_FILE $GROUP_AUTHTOKEN auth_type password

GROUP_CACHE="cache"
iniset $CONF_FILE $GROUP_CACHE enabled True

if [[ -f "$NOVA_CONF" ]]; then
    # NOTE(ft): use swift instead internal s3 server if enabled
    if [[ -n $(openstack catalog show object-store 2>/dev/null) ]] &&
            [[ -n $(openstack catalog show s3 2>/dev/null) ]]; then
        s3_host="127.0.0.1"
        if ini_has_option "$NOVA_CONF" DEFAULT "s3_host"; then
            s3_host=$(iniget $NOVA_CONF DEFAULT $option_name)
        fi
        s3_port="3334"
        if ini_has_option "$NOVA_CONF" DEFAULT "s3_port"; then
            s3_port=$(iniget $NOVA_CONF DEFAULT $option_name)
        fi
        s3_proto="http"
        if ini_has_option "$NOVA_CONF" DEFAULT "s3_use_ssl"; then
            s3_use_ssl=$(iniget $NOVA_CONF DEFAULT $option_name)
            s3_use_ssl=`echo $s3_use_ssl | awk '{print toupper($0)}'`
            if [[ $s3_use_ssl == "TRUE" ]]; then
                s3_proto="https"
            fi
        fi
        iniset $CONF_FILE DEFAULT s3_url "$s3_proto://$s3_host:$s3_port"

    fi
fi

#init cache dir
echo Creating signing dir
sudo mkdir -p $AUTH_CACHE_DIR
sudo chown $USER $AUTH_CACHE_DIR
sudo rm -f $AUTH_CACHE_DIR/*

#init data dir
echo Creating data dir
sudo mkdir -p $DATA_DIR
sudo chown $USER $DATA_DIR
sudo rm -f $DATA_DIR/*

#install it
echo Installing package
if [[ -z "$VIRTUAL_ENV" ]]; then
  SUDO_PREFIX="sudo"
  if ! command -v pip >/dev/null; then
    sudo apt-get install python-pip
  fi
fi
$SUDO_PREFIX pip install -e ./
$SUDO_PREFIX rm -rf build ec2_api.egg-info

#recreate database
echo Setuping database
PACKAGE_MANAGER_SELECTED=0
while [ $PACKAGE_MANAGER_SELECTED -eq 0 ]
do
    printf "Enter the package manager you use <rpm|deb> "
    read PACKAGE_MANAGER
    if [ $PACKAGE_MANAGER = "rpm" ] || [ $PACKAGE_MANAGER = "deb" ] ; then
        PACKAGE_MANAGER_SELECTED=1
    else
        echo "The package manager you entered \"${PACKAGE_MANAGER}\" is not in <rpm|deb>"
    fi
done

$SUDO_PREFIX tools/db/ec2api-db-setup $PACKAGE_MANAGER
