#!/bin/sh -e

function is_hrv_event() {
    cond="${1//\"/}"
    if [[ $cond == POLICY* ]] ;
    then
        return $SUCCESS
    fi
    return $FAILURE        
}


function process_hrv() {

    ## POLICY VIOLATION VARIABLES
    APP_NAME="${1//\"/}"
    APP_ID="${2//\"/}"
    PVN_ALERT_TIME="${3//\"/}"
    PRIORITY="${4//\"/}"
    SEVERITY="${5//\"/}"
    TAG="${6//\"/}"
    HEALTH_RULE_NAME="${7//\"/}"
    HEALTH_RULE_ID="${8//\"/}"
    PVN_TIME_PERIOD_IN_MINUTES="${9//\"/}"
    AFFECTED_ENTITY_TYPE="${10//\"/}"
    AFFECTED_ENTITY_NAME="${11//\"/}"
    AFFECTED_ENTITY_ID="${12//\"/}"
    NUMBER_OF_EVALUATION_ENTITIES="${13//\"/}"
    
              
    ## EVENT_DETAIL VARIABLES
    EVENT_DETAIL="{ \"Application Name\": \"$APP_NAME\",
    \"Policy Violation Alert Time\": \"$PVN_ALERT_TIME\",
    \"Severity\": \"$SEVERITY\",
    \"Priority\": \"$PRIORITY\",
    \"Name of Violated Health Rule\": \"$HEALTH_RULE_NAME\",
    \"Affected Entity Type\": \"$AFFECTED_ENTITY_TYPE\",
    \"Name of Affected Entity\": \"$AFFECTED_ENTITY_NAME\","
    
    ## SET CURRENT PARAMETER LOCATION
    CURP=13
    
    ## LOOP THROUGH AND GET VARIABLES OF ALL EVALUATION ENTITIES
    for i in `seq 1 ${NUMBER_OF_EVALUATION_ENTITIES}`
    do
        EVENT_DETAIL=$EVENT_DETAIL"""\"EVALUATION ENTITY #"""$i"""\":\"\","
    
        ((CURP = 1 + $CURP))
        EVALUATION_ENTITY_TYPE="${!CURP}"
        EVALUATION_ENTITY_TYPE="${EVALUATION_ENTITY_TYPE//\"/}"
    
        EVENT_DETAIL=$EVENT_DETAIL"""\"Evaluation Entity Type\": \""""$EVALUATION_ENTITY_TYPE"""\","
    
        ((CURP = 1 + $CURP))
        EVALUATION_ENTITY_NAME="${!CURP}"
        EVALUATION_ENTITY_NAME="${EVALUATION_ENTITY_NAME//\"/}"    
    
        EVENT_DETAIL=$EVENT_DETAIL"""\"Evaluation Entity Name\": \""""$EVALUATION_ENTITY_NAME"""\","
    
        ((CURP = 1 + $CURP))
        EVALUATION_ENTITY_ID="${!CURP}"
        EVALUATION_ENTITY_ID="${EVALUATION_ENTITY_ID//\"/}"
    
        EVENT_DETAIL=$EVENT_DETAIL"""\"Evaluation Entity ID\": \""""$EVALUATION_ENTITY_ID"""\","
        
        ((CURP = 1 + $CURP))
        NUMBER_OF_TRIGGERED_CONDITIONS_PER_EVALUATION_ENTITY="${!CURP}"
        NUMBER_OF_TRIGGERED_CONDITIONS_PER_EVALUATION_ENTITY="${NUMBER_OF_TRIGGERED_CONDITIONS_PER_EVALUATION_ENTITY//\"/}"
    
        EVENT_DETAIL=$EVENT_DETAIL"""\"Number of Triggered Conditions for """$EVALUATION_ENTITY_NAME"""\": \""""$NUMBER_OF_TRIGGERED_CONDITIONS_PER_EVALUATION_ENTITY"""\","
    
        ## GET VARIABLES OF TRIGGERED CONDITIONS
        for trig in `seq 1 $NUMBER_OF_TRIGGERED_CONDITIONS_PER_EVALUATION_ENTITY`
        do
    
            EVENT_DETAIL=$EVENT_DETAIL"""\"Triggered Condition #"""$trig"""\":\"\","
    
            ((CURP = 1 + $CURP))
            SCOPE_TYPE_x="${!CURP}"
            SCOPE_TYPE_x="${SCOPE_TYPE_x//\"/}"
            
            EVENT_DETAIL=$EVENT_DETAIL"""\"Scope Type\": \""""$SCOPE_TYPE_x"""\","
    
            ((CURP = 1 + $CURP))
            SCOPE_NAME_x="${!CURP}"
            SCOPE_NAME_x="${SCOPE_NAME_x//\"/}"
            
            EVENT_DETAIL=$EVENT_DETAIL"""\"Scope Name\": \""""$SCOPE_NAME_x"""\","
    
            ((CURP = 1 + $CURP))
            SCOPE_ID_x="${!CURP}"
            SCOPE_ID_x="${SCOPE_ID_x//\"/}"
    
            EVENT_DETAIL=$EVENT_DETAIL"""\"Scope ID\": \""""$SCOPE_ID_x"""\","
    
            ((CURP = 1 + $CURP))
            CONDITION_NAME_x="${!CURP}"
            CONDITION_NAME_x="${CONDITION_NAME_x//\"/}"
    
            EVENT_DETAIL=$EVENT_DETAIL"""\"Condition Name\": \""""$CONDITION_NAME_x"""\","
    
            ((CURP = 1 + $CURP))
            CONDITION_ID_x="${!CURP}"
            CONDITION_ID_x="${CONDITION_ID_x//\"/}"
    
            EVENT_DETAIL=$EVENT_DETAIL"""\"Condition ID\": \""""$CONDITION_ID_x"""\","
    
            ((CURP = 1 + $CURP))
            OPERATOR_x="${!CURP}"
            OPERATOR_x="${OPERATOR_x//\"/}"
    
            if [ "$OPERATOR_x" = "LESS_THAN" ]; then
                OPERATOR_x="<"
            elif [ "$OPERATOR_x" = "LESS_THAN_EQUALS" ]; then
                OPERATOR_x="<="
            elif [ "$OPERATOR_x" = "GREATER_THAN" ]; then
                OPERATOR_x=">"
            elif [ "$OPERATOR_x" = "GREATER_THAN_EQUALS" ]; then
                OPERATOR_x=">="
            elif [ "$OPERATOR_x" = "EQUALS" ]; then
                OPERATOR_x="=="
            elif [ "$OPERATOR_x" = "NOT_EQUALS" ]; then
                OPERATOR_x="!="
            fi 
        
            EVENT_DETAIL=$EVENT_DETAIL"""\"Operator\": \""""$OPERATOR_x"""\","
    
            ((CURP = 1 + $CURP))
            CONDITION_UNIT_TYPE_x="${!CURP}"
            CONDITION_UNIT_TYPE_x="${CONDITION_UNIT_TYPE_x//\"/}"
    
            EVENT_DETAIL=$EVENT_DETAIL"""\"Condition Unit Type\": \""""$CONDITION_UNIT_TYPE_x"""\","
    
            ISBASELINE=${CONDITION_UNIT_TYPE_x:0:9}
    
            EVENT_DETAIL=$EVENT_DETAIL"""\"Condition Unit Type SubString\": \""""$ISBASELINE"""\","
    
            if [ "$ISBASELINE" == "BASELINE_" ]
            then
                ((CURP = 1 + $CURP))
                USE_DEFAULT_BASELINE_x="${!CURP}"
                USE_DEFAULT_BASELINE_x="${USE_DEFAULT_BASELINE_x//\"/}"
    
                EVENT_DETAIL=$EVENT_DETAIL"""\"Is Default Baseline?\" : \""""$USE_DEFAULT_BASELINE_x"""\","
    
                if [ "$USE_DEFAULT_BASELINE_x" == "false" ]
                then
                    ((CURP = 1 + $CURP))
                    BASELINE_NAME_x="${!CURP}"
                    BASELINE_NAME_x="${BASELINE_NAME_x//\"/}"
    
                    EVENT_DETAIL=$EVENT_DETAIL"""\"Baseline Name\": \""""$BASELINE_NAME_x"""\","
    
                    ((CURP = 1 + $CURP))
                    BASELINE_ID_x="${!CURP}"
                    BASELINE_ID_x="${BASELINE_ID_x//\"/}"
    
                    EVENT_DETAIL=$EVENT_DETAIL"""\"Baseline ID\": \""""$BASELINE_ID_x"""\","
                fi
            fi
    
            ((CURP = 1 + $CURP))
            THRESHOLD_VALUE_x="${!CURP}"
            THRESHOLD_VALUE_x="${THRESHOLD_VALUE_x//\"/}"
    
            EVENT_DETAIL=$EVENT_DETAIL"""\"Threshold Value\": \""""$THRESHOLD_VALUE_x"""\","
            ##EVENT_DETAIL=$EVENT_DETAIL"""\""""$CONDITION_NAME_x""" """$OPERATOR_x""" """$THRESHOLD_VALUE_x"""\":\"\","
    
            ((CURP = 1 + $CURP))
            OBSERVED_VALUE_x="${!CURP}"
            OBSERVED_VALUE_x="${OBSERVED_VALUE_x//\"/}"
    
            EVENT_DETAIL=$EVENT_DETAIL"""\"Observed Value\" : \""""$OBSERVED_VALUE_x"""\","
    
        done
    done
    
    ((CURP = 1 + $CURP))
    SUMMARY_MESSAGE="${!CURP}"
    SUMMARY_MESSAGE="${SUMMARY_MESSAGE//\"/}"
    
    EVENT_DETAIL=$EVENT_DETAIL"""\"Summary Message\": \""""$SUMMARY_MESSAGE"""\","
    
    ((CURP = 1 + $CURP))
    INCIDENT_ID="${!CURP}"
    INCIDENT_ID="${INCIDENT_ID//\"/}"
    
    ((CURP = 1 + $CURP))
    DEEP_LINK_URL="${!CURP}"
    DEEP_LINK_URL="${DEEP_LINK_URL//\"/}${INCIDENT_ID}"
    
    EVENT_DETAIL=$EVENT_DETAIL"""\"Incident URL\": \""""$DEEP_LINK_URL""$INCIDENT_ID"""\","
    
    ((CURP = 1 + $CURP))
    POLICY_TYPE="${!CURP}"
    POLICY_TYPE="${POLICY_TYPE//\"/}"
        
    EVENT_DETAIL=$EVENT_DETAIL"""\"Event Type\": \""""$POLICY_TYPE"""\","

    ((CURP = 1 + $CURP))
    ACCOUNT_NAME="${!CURP}"
    ACCOUNT_NAME="${ACCOUNT_NAME//\"/}"

    EVENT_DETAIL=$EVENT_DETAIL"""\"Account Name\": \""""$ACCOUNT_NAME"""\","

    ((CURP = 1 + $CURP))
    ACCOUNT_ID="${!CURP}"
    ACCOUNT_ID="${ACCOUNT_ID//\"/}"

    EVENT_DETAIL=$EVENT_DETAIL"""\"Account Id\": \""""$ACCOUNT_ID"""\""

    EVENT_DETAIL=$EVENT_DETAIL"""}"
}


function process_non_hrv() {

    ## POLICY VIOLATION VARIABLES
    APP_NAME="${1//\"/}"
    APP_ID="${2//\"/}"
    EN_TIME="${3//\"/}"
    PRIORITY="${4//\"/}"
    SEVERITY="${5//\"/}"
    TAG="${6//\"/}"
    EN_NAME="${7//\"/}"
    EN_ID="${8//\"/}"
    EN_INTERVAL_IN_MINUTES="${9//\"/}"
    NUMBER_OF_EVENT_TYPES="${10//\"/}"

    ## EVENT_DETAIL VARIABLES
    EVENT_DETAIL="{ \"Application Name\": \"$APP_NAME\",
    \"Event Notification Time\": \"$EN_TIME\",
    \"Severity\": \"$SEVERITY\",
    \"Priority\": \"$PRIORITY\",
    \"Event Notification Name\": \"$EN_NAME\","



    ## SET CURRENT PARAMETER LOCATION
    CURP=10

    for i in `seq 1 ${NUMBER_OF_EVENT_TYPES}`
    do
        EVENT_DETAIL=$EVENT_DETAIL"""\"EVENT TYPE #"""$i"""\":\"\","
    
        ((CURP = 1 + $CURP))
        EVENT_TYPE="${!CURP}"
        EVENT_TYPE="${EVENT_TYPE//\"/}"
    
        EVENT_DETAIL=$EVENT_DETAIL"""\"Event Type\": \""""$EVENT_TYPE"""\","
    
        ((CURP = 1 + $CURP))
        EVENT_TYPE_NUM="${!CURP}"
        EVENT_TYPE_NUM="${EVENT_TYPE_NUM//\"/}"    
    
        EVENT_DETAIL=$EVENT_DETAIL"""\"Event Type Num\": \""""$EVENT_TYPE_NUM"""\","
    done 

    ((CURP = 1 + $CURP))
    NUMBER_OF_EVENT_SUMMARIES="${!CURP}"
    NUMBER_OF_EVENT_SUMMARIES="${NUMBER_OF_EVENT_SUMMARIES//\"/}"

    EVENT_DETAIL=$EVENT_DETAIL"""\"Number of Event Summaries for Event Type """$EVENT_TYPE"""\": \""""$NUMBER_OF_EVENT_SUMMARIES"""\","
    
    ## GET VARIABLES OF TRIGGERED CONDITIONS
    for summ in `seq 1 $NUMBER_OF_EVENT_SUMMARIES`
    do
        EVENT_DETAIL=$EVENT_DETAIL"""\"Event Summary #"""$summ"""\":\"\","

        ((CURP = 1 + $CURP))
        EVENT_SUMMARY_ID_x="${!CURP}"
        EVENT_SUMMARY_ID_x="${EVENT_SUMMARY_ID_x//\"/}"
        
        EVENT_DETAIL=$EVENT_DETAIL"""\"Event Summary\": \""""$EVENT_SUMMARY_ID_x"""\","

        ((CURP = 1 + $CURP))
        EVENT_SUMMARY_TIME_x="${!CURP}"
        EVENT_SUMMARY_TIME_x="${EVENT_SUMMARY_TIME_x//\"/}"
        
        EVENT_DETAIL=$EVENT_DETAIL"""\"Event Summary Time\": \""""$EVENT_SUMMARY_TIME_x"""\","

        ((CURP = 1 + $CURP))
        EVENT_SUMMARY_TYPE_x="${!CURP}"
        EVENT_SUMMARY_TYPE_x="${EVENT_SUMMARY_TYPE_x//\"/}"

        EVENT_DETAIL=$EVENT_DETAIL"""\"Event Summary Type\": \""""$EVENT_SUMMARY_TYPE_x"""\","

        ((CURP = 1 + $CURP))
        EVENT_SUMMARY_SEVERITY_x="${!CURP}"
        EVENT_SUMMARY_SEVERITY_x="${EVENT_SUMMARY_SEVERITY_x//\"/}"

        EVENT_DETAIL=$EVENT_DETAIL"""\"Event Summary Severity\": \""""$EVENT_SUMMARY_SEVERITY_x"""\","
        ((CURP = 1 + $CURP))
        EVENT_SUMMARY_STRING_x="${!CURP}"
        EVENT_SUMMARY_STRING_x="${EVENT_SUMMARY_STRING_x//\"/}"

        EVENT_DETAIL=$EVENT_DETAIL"""\"Event Summary String\": \""""$EVENT_SUMMARY_STRING_x"""\","

    done    

    ((CURP = 1 + $CURP))
    DEEP_LINK_URL="${!CURP}"
    DEEP_LINK_URL="${DEEP_LINK_URL//\"/}"
    
    EVENT_DETAIL=$EVENT_DETAIL"""\"Deep link URL\": \""""$DEEP_LINK_URL"""\","

    ((CURP = 1 + $CURP))
    ACCOUNT_NAME="${!CURP}"
    ACCOUNT_NAME="${ACCOUNT_NAME//\"/}"

    EVENT_DETAIL=$EVENT_DETAIL"""\"Account Name\": \""""$ACCOUNT_NAME"""\","

    ((CURP = 1 + $CURP))
    ACCOUNT_ID="${!CURP}"
    ACCOUNT_ID="${ACCOUNT_ID//\"/}"

    EVENT_DETAIL=$EVENT_DETAIL"""\"Account Id\": \""""$ACCOUNT_ID"""\""

    EVENT_DETAIL=$EVENT_DETAIL"""}"   

}


function usage() {
  echo "\n*************************************************************************************************************************\n"
  echo "                                                    APPDYNAMICS Alerts                                                                           "  
  echo "\nFor description about each field, please refer https://docs.appdynamics.com/display/PRO40/Build+an+Alerting+Extension\n"  
  echo "\n*************************************************************************************************************************\n"  
  echo "    For Health Rule Violation Event ::"
  echo "        APP_NAME "
  echo "        APP_ID "
  echo "        PVN_ALERT_TIME "
  echo "        PRIORITY "
  echo "        SEVERITY "
  echo "        TAG "
  echo "        HEALTH_RULE_NAME "
  echo "        HEALTH_RULE_ID "
  echo "        PVN_TIME_PERIOD_IN_MINUTES "
  echo "        AFFECTED_ENTITY_TYPE "
  echo "        AFFECTED_ENTITY_NAME "
  echo "        AFFECTED_ENTITY_ID "
  echo "        SUMMARY_MESSAGE "
  echo "        INCIDENT_ID "
  echo "        DEEP_LINK_URL "
  echo "        ACCOUNT_NAME "
  echo "        ACCOUNT_ID "
  echo "        POLICY_TYPE "
  echo "        EVENT_DETAIL => A JSON payload for a detailed view of the event."
  echo "        IS_HRV => A flag to differentiate between health rule violation(hrv) and non-hrv events. For HRV this flag = 1"

  echo "\n***********************************************************************************************************************\n"
  echo "     For Non Health Rule Violation Event ::"
  echo "        APP_NAME "
  echo "        APP_ID "
  echo "        EN_TIME "
  echo "        PRIORITY "
  echo "        SEVERITY "
  echo "        TAG "
  echo "        EN_NAME "
  echo "        EN_ID "
  echo "        EN_INTERVAL_IN_MINUTES "
  echo "        DEEP_LINK_URL "
  echo "        ACCOUNT_NAME "
  echo "        ACCOUNT_ID "
  echo "        EVENT_DETAIL => A JSON payload for a detailed view of the event."
  echo "        IS_HRV => A flag to differentiate between health rule violation(hrv) and non-hrv events. For non-HRV this flag = 0"
  echo "\n***********************************************************************************************************************\n"
}

########################################

SUCCESS=0
FAILURE=-1


if [ "$1" == "-h" ]; then
    usage
    exit 0
fi

#Default to non-hrv event
IS_HRV=0

# Check the third to last argument to determine if event is HRV
if is_hrv_event ${@:(-3):1} = $SUCCESS  
then    
    echo "Processing a Health Rule Violation event."
    IS_HRV=1
    process_hrv "$@"
    export IS_HRV APP_NAME APP_ID PVN_ALERT_TIME PRIORITY SEVERITY TAG HEALTH_RULE_NAME HEALTH_RULE_ID PVN_TIME_PERIOD_IN_MINUTES 
    export AFFECTED_ENTITY_TYPE AFFECTED_ENTITY_NAME AFFECTED_ENTITY_ID SUMMARY_MESSAGE INCIDENT_ID DEEP_LINK_URL POLICY_TYPE ACCOUNT_NAME ACCOUNT_ID EVENT_DETAIL
        
else
    echo "Processing a Non-Health Rule event."
    process_non_hrv "$@"
    export IS_HRV APP_NAME APP_ID EN_TIME PRIORITY SEVERITY TAG EN_NAME EN_ID EN_INTERVAL_IN_MINUTES EVENT_DETAIL DEEP_LINK_URL ACCOUNT_NAME ACCOUNT_ID
fi      



