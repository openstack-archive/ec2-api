# ec2-api.sh - DevStack extras script to install ec2-api

if is_service_enabled ec2-api; then
    if [[ "$1" == "source" ]]; then
        # Initial source
        source $TOP_DIR/lib/ec2-api
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
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
fi
