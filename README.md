# custom-action-scripts
This document contains the parsing logic for custom actions.

## 1. Description
This utitlity is shipped with two scripts
 a. wrapper.sh
 b. appd-alert.sh
 
The appd-alert.sh contains the logic to parse the the arguments passed to the custom actions. This script exposes different environment 
variables which can then be used in the wrapper.sh. 

The environment variables exposed in case of Health Rule Violation Events are 

APP_NAME
APP_ID
PVN_ALERT_TIME
PRIORITY
SEVERITY 
TAG
HEALTH_RULE_NAME
HEALTH_RULE_ID
PVN_TIME_PERIOD_IN_MINUTES
AFFECTED_ENTITY_TYPE
AFFECTED_ENTITY_NAME
AFFECTED_ENTITY_ID
SUMMARY_MESSAGE
INCIDENT_ID
DEEP_LINK_URL
ACCOUNT_NAME
ACCOUNT_ID 
EVENT_DETAIL => A JSON payload for a detailed view of the event.
IS_HRV => A flag to differentiate between health rule violation(hrv) and non-hrv events. For HRV this flag = 1

For more information on what the above field means please check [this](https://docs.appdynamics.com/display/PRO42/Build+a+Custom+Action) doc


##2. Configuration

Let's say you have to write a custom action to integrate the events in AppDynamics with a third party tool say foo-bar.The entire logic of 
sending the event to foo-bar needs to be implemented in the wrapper.sh using the environment variables exposed above. 

As an example, check [here](https://github.com/Appdynamics/hpopenview-alerting-extension/blob/master/wrapper.sh) to see how the wrapper.sh has been implemented to send events to a third party tool called hp-openview 




##3. Installation

Again,assume that you are want to send events to a third party tool say foo-bar. Below are the steps 
that you will have to follow to use these scripts

1. Create a directory say foo-bar in the <controller_dir>/custom/actions
2. Place the wrapper.sh and appd_alert.sh in the foo-bar directory. 
3. If you see a custom.xml in the <controller_dir>/custom/actions, add the following entry

      <action>
        <type>foo-bar</type>
        <executable>wrapper.sh</executable>
      </action>
      
   Create a new custom.xml in the <controller_dir>/custom/actions if there isn't one already  
   
     <custom-actions>
        <action>
     	    <type>foo-bar</type>
          <executable>wrapper.sh</executable>
         </action>
     </custom-actions>
   


Now you can use this foo-bar custom action from the controller. 





