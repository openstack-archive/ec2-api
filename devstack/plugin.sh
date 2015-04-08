# lib/ec2-api

# Dependencies:
# ``functions`` file
# ``DEST``, ``DATA_DIR``, ``STACK_USER`` must be defined

# ``stack.sh`` calls the entry points in this order:
#
# install_ec2api
# configure_ec2api
# start_ec2api
# stop_ec2api


# Save trace setting
XTRACE=$(set +o | grep xtrace)
set -o xtrace


# Defaults
# --------

# Set up default directories
EC2API_DIR=$DEST/ec2-api
EC2API_CONF_DIR=${EC2API_CONF_DIR:-/etc/ec2api}
EC2API_CONF_FILE=${EC2API_CONF_DIR}/ec2api.conf
EC2API_DEBUG=${EC2API_DEBUG:-True}
EC2API_STATE_PATH=${EC2API_STATE_PATH:=$DATA_DIR/ec2api}

EC2API_SERVICE_PORT=${EC2API_SERVICE_PORT:-8788}
EC2API_S3_SERVICE_PORT=${EC2API_S3_SERVICE_PORT:-3334}

EC2API_RABBIT_VHOST=${EC2API_RABBIT_VHOST:-''}

EC2API_ADMIN_USER=${EC2API_ADMIN_USER:-ec2api}

EC2API_KEYSTONE_SIGNING_DIR=${EC2API_KEYSTONE_SIGNING_DIR:-/tmp/keystone-signing-ec2api}

# Support entry points installation of console scripts
if [[ -d $EC2API_DIR/bin ]]; then
    EC2API_BIN_DIR=$EC2API_DIR/bin
else
    EC2API_BIN_DIR=$(get_python_exec_prefix)
fi


function recreate_endpoint {
    local endpoint=$1
    local description=$2
    local port=$3

    if [[ "$KEYSTONE_CATALOG_BACKEND" = 'sql' ]]; then

        # Remove nova's ec2 service/endpoint
        local endpoint_id=$(openstack endpoint list \
            --column "ID" \
            --column "Region" \
            --column "Service Name" \
            | grep " $REGION_NAME " \
            | grep " $endpoint " | get_field 1)
        if [[ -n "$endpoint_id" ]]; then
            openstack endpoint delete $endpoint_id
        fi
        local service_id=$(openstack service list \
            -c "ID" -c "Name" \
            | grep " $endpoint " | get_field 1)
        if [[ -n "$service_id" ]]; then
            openstack service delete $service_id
        fi

        local service_id=$(openstack service create \
            $endpoint \
            --name "$endpoint" \
            --description="$description" \
            -f value -c id)
        openstack endpoint create \
            $service_id \
            --region "$REGION_NAME" \
            --publicurl "$SERVICE_PROTOCOL://$SERVICE_HOST:$port/" \
            --adminurl "$SERVICE_PROTOCOL://$SERVICE_HOST:$port/" \
            --internalurl "$SERVICE_PROTOCOL://$SERVICE_HOST:$port/"
    fi
}


# create_ec2api_accounts() - Set up common required ec2api accounts
#
# Tenant      User       Roles
# ------------------------------
# service     ec2api     admin
function create_ec2api_accounts() {
    if ! is_service_enabled key; then
        return
    fi

    SERVICE_TENANT=$(openstack project list | awk "/ $SERVICE_TENANT_NAME / { print \$2 }")
    ADMIN_ROLE=$(openstack role list | awk "/ admin / { print \$2 }")

    EC2API_USER=$(openstack user create \
        $EC2API_ADMIN_USER \
        --password "$SERVICE_PASSWORD" \
        --project $SERVICE_TENANT \
        --email ec2api@example.com \
        | grep " id " | get_field 2)

    openstack role add \
        $ADMIN_ROLE \
        --project $SERVICE_TENANT \
        --user $EC2API_USER

    recreate_endpoint "ec2" "EC2 Compatibility Layer" $EC2API_SERVICE_PORT
    if ! is_service_enabled swift3; then
        recreate_endpoint "s3" "S3" $EC2API_S3_SERVICE_PORT
    fi
}


function mkdir_chown_stack {
    if [[ ! -d "$1" ]]; then
        sudo mkdir -p "$1"
    fi
    sudo chown $STACK_USER "$1"
}


function configure_ec2api_rpc_backend() {
    # Configure the rpc service.
    iniset_rpc_backend ec2api $EC2API_CONF_FILE DEFAULT

    # TODO(ruhe): get rid of this ugly workaround.
    inicomment $EC2API_CONF_FILE DEFAULT rpc_backend

    # Set non-default rabbit virtual host if required.
    if [[ -n "$EC2API_RABBIT_VHOST" ]]; then
        iniset $EC2API_CONF_FILE DEFAULT rabbit_virtual_host $EC2API_RABBIT_VHOST
    fi
}

function configure_ec2api_networking {
    # Use keyword 'public' if ec2api external network was not set.
    # If it was set but the network is not exist then
    # first available external network will be selected.
    local ext_net=${EC2API_EXTERNAL_NETWORK:-'public'}
    # Configure networking options for ec2api
    if [[ -n "$ext_net" ]]; then
        iniset $EC2API_CONF_FILE DEFAULT external_network $ext_net
    fi

    if [[ ,${ENABLED_SERVICES} =~ ,"q-" ]]; then
        iniset $EC2API_CONF_FILE DEFAULT full_vpc_support True
    else
        iniset $EC2API_CONF_FILE DEFAULT full_vpc_support False
    fi
}

# Entry points
# ------------

# configure_ec2api() - Set config files, create data dirs, etc
function configure_ec2api {
    mkdir_chown_stack "$EC2API_CONF_DIR"

    # Generate ec2api configuration file and configure common parameters.
    oslo-config-generator --namespace keystonemiddleware.auth_token \
                          --namespace ec2api \
                          --namespace oslo.db \
                          --namespace oslo.messaging \
                          > $EC2API_CONF_FILE
    cp $EC2API_DIR/etc/ec2api/api-paste.ini $EC2API_CONF_DIR

    cleanup_ec2api

    iniset $EC2API_CONF_FILE DEFAULT debug $EC2API_DEBUG
    iniset $EC2API_CONF_FILE DEFAULT use_syslog $SYSLOG
    iniset $EC2API_CONF_FILE DEFAULT state_path EC2API_STATE_PATH


    # ec2api Api Configuration
    #-------------------------

    # Setup keystone_authtoken section
    iniset $EC2API_CONF_FILE keystone_authtoken auth_uri "http://${KEYSTONE_AUTH_HOST}:5000/v2.0"
    iniset $EC2API_CONF_FILE keystone_authtoken auth_host $KEYSTONE_AUTH_HOST
    iniset $EC2API_CONF_FILE keystone_authtoken auth_port $KEYSTONE_AUTH_PORT
    iniset $EC2API_CONF_FILE keystone_authtoken auth_protocol $KEYSTONE_AUTH_PROTOCOL
    iniset $EC2API_CONF_FILE keystone_authtoken cafile $KEYSTONE_SSL_CA
    iniset $EC2API_CONF_FILE keystone_authtoken admin_tenant_name $SERVICE_TENANT_NAME
    iniset $EC2API_CONF_FILE keystone_authtoken admin_user $EC2API_ADMIN_USER
    iniset $EC2API_CONF_FILE keystone_authtoken admin_password $SERVICE_PASSWORD
    iniset $EC2API_CONF_FILE keystone_authtoken signing_dir $EC2API_KEYSTONE_SIGNING_DIR

    iniset $EC2API_CONF_FILE DEFAULT admin_tenant_name $SERVICE_TENANT_NAME
    iniset $EC2API_CONF_FILE DEFAULT admin_user $EC2API_ADMIN_USER
    iniset $EC2API_CONF_FILE DEFAULT admin_password $SERVICE_PASSWORD

    iniset $EC2API_CONF_FILE DEFAULT keystone_url "http://${KEYSTONE_AUTH_HOST}:35357/v2.0"
    iniset $EC2API_CONF_FILE DEFAULT region_list "$REGION_NAME"

    if is_service_enabled swift3; then
        iniset $EC2API_CONF_FILE DEFAULT s3_port "$S3_SERVICE_PORT"
    else
        iniset $EC2API_CONF_FILE DEFAULT s3_port "$EC2API_S3_SERVICE_PORT"
    fi
    iniset $EC2API_CONF_FILE DEFAULT s3_host "$SERVICE_HOST"

    configure_ec2api_rpc_backend

    # configure the database.
    iniset $EC2API_CONF_FILE database connection `database_connection_url ec2api`

    configure_ec2api_networking

    # metadata configuring
    if [[ ,${ENABLED_SERVICES} =~ ,"q-" ]]; then
        # with neutron
        iniset $Q_META_CONF_FILE DEFAULT nova_metadata_port 8789
    else
        # with nova-network
        iniset $NOVA_CONF DEFAULT metadata_port 8789
        iniset $NOVA_CONF neutron service_metadata_proxy True
    fi
}


# init_ec2api() - Initialize databases, etc.
function init_ec2api() {
    # (re)create ec2api database
    recreate_database ec2api utf8

    $EC2API_BIN_DIR/ec2-api-manage --config-file $EC2API_CONF_FILE db_sync
}


# install_ec2api() - Collect source and prepare
function install_ec2api() {
    # TODO(ruhe): use setup_develop once ec2api requirements match with global-requirement.txt
    # both functions (setup_develop and setup_package) are defined at:
    # http://git.openstack.org/cgit/openstack-dev/devstack/tree/functions-common
    setup_package $EC2API_DIR -e

    # NOTE(andrey-mp): temporary install euca2ools
    # waiting for review https://review.openstack.org/#/c/169027/
    # that review adds euca2ools installation into devstack
    # scripts with tempest. euca2ools are needed for bundling image
    # in tempest preparation scripts.
    is_package_installed euca2ools || install_package euca2ools
}


# start_ec2api() - Start running processes, including screen
function start_ec2api() {
    screen_it ec2-api "cd $EC2API_DIR && $EC2API_BIN_DIR/ec2-api --config-file $EC2API_CONF_DIR/ec2api.conf"
    screen_it ec2-api-metadata "cd $EC2API_DIR && $EC2API_BIN_DIR/ec2-api-metadata --config-file $EC2API_CONF_DIR/ec2api.conf"
    screen_it ec2-api-s3 "cd $EC2API_DIR && $EC2API_BIN_DIR/ec2-api-s3 --config-file $EC2API_CONF_DIR/ec2api.conf"
}


# stop_ec2api() - Stop running processes
function stop_ec2api() {
    # Kill the ec2api screen windows
    screen -S $SCREEN_NAME -p ec2-api -X kill
    screen -S $SCREEN_NAME -p ec2-api-metadata -X kill
    screen -S $SCREEN_NAME -p ec2-api-s3 -X kill
}

function cleanup_ec2api() {

    # Cleanup keystone signing dir
    sudo rm -rf $EC2API_KEYSTONE_SIGNING_DIR
}

# main dispatcher
if [[ "$1" == "stack" && "$2" == "install" ]]; then
    echo_summary "Installing ec2-api"
    install_ec2api
elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    echo_summary "Configuring ec2-api"
    configure_ec2api
    create_ec2api_accounts
elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
    echo_summary "Initializing ec2-api"
    init_ec2api
    start_ec2api
fi

if [[ "$1" == "unstack" ]]; then
    stop_ec2api
    cleanup_ec2api
fi

# Restore xtrace
$XTRACE

# Local variables:
# mode: shell-script
# End:
