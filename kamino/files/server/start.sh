#!/bin/sh

TEMP=$( getopt -o "a:" --long "architecture:" -- "$@" )
eval set -- "${TEMP}"

while true
do
    case "$1" in
        -a|--architecture)
            case "$2" in
                symbolic|metapc.xml)
                    ARCH="$2"
                    shift 2
                    ;;
                *)
                    printf -- "Invalid architecture '%s'\n" "$2"
                    exit 1
                    ;;
            esac
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Internal error!"
            exit 1
            ;;
    esac
done

CMD="/usr/bin/java -Xmx2048M -javaagent:./jamm-0.2.5.jar -Xss2m -Djava.library.path=./lib -Dlog4j.configurationFile=file:log4j2.xml -jar ./kam1n0.jar --deamon -cmd=start -dir=/data -arch=${ARCH}"

terminate_kamino() {
    if ps ${KAMINO_PID} 2>/dev/null 1>/dev/null
    then
        echo "Terminating Kamino (PID ${KAMINO_PID}) ..."
        kill -15 ${KAMINO_PID}

        TIMEOUT=5
        while ps ${KAMINO_PID} 2>/dev/null 1>/dev/null
        do
            sleep 1
            TIMEOUT=$(( ${TIMEOUT} - 1 ))
            if [ ${TIMEOUT} -le 0 ]
            then
                echo "Kamino did not terminate, killing it ..."
                break
            fi
        done

        while ps ${KAMINO_PID} 2>/dev/null 1>/dev/null
        do
            echo "Killing Kamino (PID ${KAMINO_PID}) with SIGKILL"
            kill -9 ${KAMINO_PID}
            sleep 1
        done
    else
        echo "Kamino (PID ${KAMINO_PID}) is already terminated"
    fi

    exit 0
}

trap 'terminate_kamino' 1 2 15

echo "Executing command: ${CMD}"
${CMD} &
KAMINO_PID=$!
echo "Kamino PID is ${KAMINO_PID}"

wait ${KAMINO_PID}
