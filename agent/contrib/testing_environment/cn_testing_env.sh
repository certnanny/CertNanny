#!/bin/bash

########################################
#
# create and manage testing environment
# for certnanny
#
# author: sebastian roland
# date: 07.03.2013
#
########################################

### BEGIN CONFIG ###

# global
ROOT='/home/vvs130/programming/git/certnanny_github/testing_env'    # path to root directory of testing env
OPENSSL='/usr/bin/openssl'                                          # path to openssl binary

# root ca
ROOT_CA_VALIDITY=1460                                               # validity in days for root ca

export ROOT                                                         # make var accessible for openssl config

### END CONFIG ###

### BEGIN FUNCTIONS ###

usage()
{
    echo "${0} init <path_to_openssl_config>"
    echo "${0} create_ee <server|email|user> <openssl>"

    exit -1
}

env_already_created()
{
    if [ -f "${ROOT}/tmp/.init_complete" ]
    then
        # return true
        return 0
    else
        # return false
        return 1
    fi
}

get_next_free_index()
{
    cert_type=${1}
    index=1

    for cert in $(ls -1 ${ROOT}/ca | grep -E 10-ee_${cert_type}_[[:digit:]]+_)
    do
        present_index=$(echo $cert | cut -d '_' -f 3)
        if [ ${present_index} -ge ${index} ]
        then
            index=$(expr ${present_index} + 1)
        fi
    done

    echo ${index}
}

# all functions used for creating a specific keystore get the cert_type
# as argument. possible values are <server|email|user>.
# as a convention filename should be "10-ee_${cert_type}_${index}_*"

create_keystore_openssl()
{
    cert_type=${1}

    # determine next available number for cert type
    index=$(get_next_free_index ${cert_type})

    # create csr
    ${OPENSSL} req -new -keyout ${ROOT}/ca/10-ee_${cert_type}_${index}_key.pem -out ${ROOT}/ca/csr/10-ee_${cert_type}_${index}_cert.csr -subj "/CN=10-ee_${cert_type}_${index}/OU=development/O=certnanny" -config ${openssl_conf} &> /dev/null
    # sign request
    ${OPENSSL} ca -name ca_int_${cert_type} -in ${ROOT}/ca/csr/10-ee_${cert_type}_${index}_cert.csr -out ${ROOT}/ca/10-ee_${cert_type}_${index}_cert.pem -config ${openssl_conf} &> /dev/null << EOF
y
y
EOF
}

create_keystore_mq()
{
    cert_type=${1}

    # determine next available number for cert type
    index=$(get_next_free_index ${cert_type})

    echo "mq keystores are currently not supported!"
}

create_keystore_java()
{
    cert_type=${1}

    # determine next available number for cert type
    index=$(get_next_free_index ${cert_type})

    echo "java keystores are currently not supported!"
}

create_keystore_windows()
{
    cert_type=${1}

    # determine next available number for cert type
    index=$(get_next_free_index ${cert_type})

    echo "windows keystores are currently not supported!"
}

create_keystore_pkcs12()
{
    cert_type=${1}

    # determine next available number for cert type
    index=$(get_next_free_index ${cert_type})

    echo "pkcs12 keystores are currently not supported!"
}

create_keystore_sap()
{
    cert_type=${1}

    # determine next available number for cert type
    index=$(get_next_free_index ${cert_type})

    echo "sap keystores are currently not supported!"
}

### END FUNCTIONS ###

### MAIN ###
arg_count=${#}
arg1=${1}
openssl_conf="${ROOT}/etc/openssl_test_env.conf"

if [ ! -x ${OPENSSL} ]
then
    echo "ERROR: '${OPENSSL}' either not existent or executable"
    exit -2
fi

case "${arg1}" in
    init)
            if [ ${arg_count} -ne 2 ]
            then
                usage
            fi

            arg_openssl_conf=${2}

            # do some checks
            if [ ! -r "${arg_openssl_conf}" ]
            then
                echo "ERROR: cannot read openssl config ('${arg_openssl_conf}')"
                exit -2
            fi

            if env_already_created
            then
                read -n 1 -p "testing environment has already been setup. create new? [y/n]: " overwrite_root
                echo ""
                case "${overwrite_root}" in
                    [yY])
                            ;;
                    *)
                            exit -3
                            ;;
                esac
            fi

            # create directory structure and files

            # check permissions
            root_parent=$(dirname ${ROOT})
            if [ ! -w ${root_parent} ]
            then
                echo "ERROR: '${root_parent}' is not writeable"
                exit -4
            fi

            rm -rf ${ROOT}
            echo "creating directory structure and files"
            mkdir -p ${ROOT}/ca/csr ${ROOT}/ca/res ${ROOT}/etc ${ROOT}/tmp
            touch ${ROOT}/ca/res/ca_database
            touch ${ROOT}/ca/res/ca_serial
            echo "01" > ${ROOT}/ca/res/ca_serial

            # copy openssl config
            echo "copying openssl config"
            cp ${arg_openssl_conf} ${openssl_conf}

            # create root ca
            echo "creating root ca"
            ${OPENSSL} req -new -x509 -days ${ROOT_CA_VALIDITY} -keyout ${ROOT}/ca/00-ca_root_key.pem -out ${ROOT}/ca/00-ca_root_cert.pem -subj '/CN=00-ca_root/OU=development/O=certnanny' -config ${openssl_conf} &> /dev/null

            # create intermediate ca's
            echo "creating intermediate ca's"
            # create csr's
            ${OPENSSL} req -new -keyout ${ROOT}/ca/01-ca_int_server_key.pem -out ${ROOT}/ca/csr/01-ca_int_server_cert.csr -subj '/CN=01-ca_int_server/OU=development/O=certnanny' -config ${openssl_conf} &> /dev/null
            ${OPENSSL} req -new -keyout ${ROOT}/ca/01-ca_int_email_key.pem -out ${ROOT}/ca/csr/01-ca_int_email_cert.csr -subj '/CN=01-ca_int_email/OU=development/O=certnanny' -config ${openssl_conf} &> /dev/null
            ${OPENSSL} req -new -keyout ${ROOT}/ca/01-ca_int_user_key.pem -out ${ROOT}/ca/csr/01-ca_int_user_cert.csr -subj '/CN=01-ca_int_user/OU=development/O=certnanny' -config ${openssl_conf} &> /dev/null
            # sign requests
            ${OPENSSL} ca -in ${ROOT}/ca/csr/01-ca_int_server_cert.csr -out ${ROOT}/ca/01-ca_int_server_cert.pem -config ${openssl_conf} &> /dev/null << EOF
y
y
EOF
            ${OPENSSL} ca -in ${ROOT}/ca/csr/01-ca_int_email_cert.csr -out ${ROOT}/ca/01-ca_int_email_cert.pem -config ${openssl_conf} &> /dev/null << EOF
y
y
EOF
            ${OPENSSL} ca -in ${ROOT}/ca/csr/01-ca_int_user_cert.csr -out ${ROOT}/ca/01-ca_int_user_cert.pem -config ${openssl_conf} &> /dev/null << EOF
y
y
EOF

            # create sscep server certificate
            echo "creating sscep server certificate"
            # create csr
            ${OPENSSL} req -new -keyout ${ROOT}/ca/02-ee_server_sscep_key.pem -out ${ROOT}/ca/csr/02-ee_server_sscep_cert.csr -subj '/CN=02-ee_server_sscep/OU=development/O=certnanny' -config ${openssl_conf} &> /dev/null
            # sign request
            ${OPENSSL} ca -name ca_int_server -in ${ROOT}/ca/csr/02-ee_server_sscep_cert.csr -out ${ROOT}/ca/02-ee_server_sscep_cert.pem -config ${openssl_conf} &> /dev/null << EOF
y
y
EOF

            # initialization complete
            touch ${ROOT}/tmp/.init_complete

            ;;

    create_ee)
            if [ ${arg_count} -ne 3 ]
            then
                usage
            fi

            if ! env_already_created
            then
                echo "ERROR: cant find testing environment. please create first with ${0} init"
                exit -5
            fi

            cert_type=${2}
            case "${cert_type}" in
                server)
                        ;;
                email)
                        ;;
                user)
                        ;;
                *)
                        echo "ERROR: '${cert_type}' is not a valid cert type"
                        exit -6
                        ;;
            esac

            keystore=${3}
            case "${keystore}" in
                openssl)
                        create_keystore_openssl ${cert_type}
                        ;;
                mq)
                        create_keystore_mq ${cert_type}
                        ;;
                java)
                        create_keystore_java ${cert_type}
                        ;;
                windows)
                        create_keystore_windows ${cert_type}
                        ;;
                pkcs12)
                        create_keystore_pkcs12 ${cert_type}
                        ;;
                sap)
                        create_keystore_sap ${cert_type}
                        ;;
                *)
                        echo "ERROR: '${keystore}' is not a valid keystore"
                        exit -7
                        ;;
            esac
            ;;

    *)
            usage
            ;;
esac
#EOF
