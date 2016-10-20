#
# Copyright 2013 AppDynamics
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#!/bin/sh -x
APP_NAME="\"ACME Book Store Application\""
APP_ID=8
EN_TIME="\"Wed Jan 04 09:36:55 PST 2012\""
PRIORITY=1
SEVERITY="\"INFO\""
TAG="\"Event Notification\""
EN_NAME="\"event-notification\""
EN_ID=2
EN_INTERVAL_IN_MINUTES=15
NUMBER_OF_EVENT_TYPES=4
EVENT_TYPE_1="\"APPLICATION_CONFIG_CHANGE\""
EVENT_TYPE_1_NUM=1
EVENT_TYPE_2="\"APP_SERVER_RESTART\""
EVENT_TYPE_2_NUM=1
EVENT_TYPE_3="\"DIAGNOSTIC_SESSION\""
EVENT_TYPE_3_NUM=1
EVENT_TYPE_4="\"STALL\""
EVENT_TYPE_4_NUM=1
NUMBER_OF_EVENT_SUMMARIES=4
EVENT_SUMMARY_1_ID=10375
EVENT_SUMMARY_1_TIME="\"Wed Jan 04 09:35:53 PST 2012\""
EVENT_SUMMARY_1_TYPE="\"STALL\""
EVENT_SUMMARY_1_SEVERITY="\"ERROR\""
EVENT_SUMMARY_1_STRING="\"Request is stalled, time elapsed since beginning of request [45258] ms.\""
EVENT_SUMMARY_2_ID=10346
EVENT_SUMMARY_2_TIME="\"Wed Jan 04 09:34:13 PST 2012\""
EVENT_SUMMARY_2_TYPE="\"DIAGNOSTIC_SESSION\""
EVENT_SUMMARY_2_SEVERITY="\"WARN\""
EVENT_SUMMARY_2_STRING="\"Starting Diagnostic Session after series of slow requests for a Business Transaction 95% (23/24) of requests were slow in the last minute starting 1/4/12 9:34 AM local time\""
EVENT_SUMMARY_3_ID=10344
EVENT_SUMMARY_3_TIME="\"Wed Jan 04 09:32:17 PST 2012\""
EVENT_SUMMARY_3_TYPE="\"APP_SERVER_RESTART\""
EVENT_SUMMARY_3_SEVERITY="\"INFO\""
EVENT_SUMMARY_3_STRING="\"Application Server JVM was re-started, 10345\""
EVENT_SUMMARY_4_ID=10340
EVENT_SUMMARY_4_TIME="\"Wed Jan 04 09:32:14 PST 2012\""
EVENT_SUMMARY_4_TYPE="\"APPLICATION_CONFIG_CHANGE\""
EVENT_SUMMARY_4_SEVERITY="\"INFO\""
EVENT_SUMMARY_4_STRING="\"Application Server environment variables changed\""
DEEP_LINK_URL="\"http://WIN-FKL67IRSIPI:9080/controller/#location=APP_EVENT_VIEWER_MODAL&eventSummary=\""
ACCOUNT_NAME="\"hello\""
ACCOUNT_ID="\"asdf23ewe3\""
. ./appd_alert.sh "${APP_NAME}" "${APP_ID}" "${EN_TIME}" "${PRIORITY}" "${SEVERITY}" "${TAG}" "${EN_NAME}" "${EN_ID}" "${EN_INTERVAL_IN_MINUTES}" "${NUMBER_OF_EVENT_TYPES}" "${EVENT_TYPE_1}" "${EVENT_TYPE_1_NUM}" "${EVENT_TYPE_2}" "${EVENT_TYPE_2_NUM}" "${EVENT_TYPE_3}" "${EVENT_TYPE_3_NUM}" "${EVENT_TYPE_4}" "${EVENT_TYPE_4_NUM}"  "${NUMBER_OF_EVENT_SUMMARIES}" "${EVENT_SUMMARY_1_ID}" "${EVENT_SUMMARY_1_TIME}" "${EVENT_SUMMARY_1_TYPE}" "${EVENT_SUMMARY_1_SEVERITY}" "${EVENT_SUMMARY_1_STRING}" "${EVENT_SUMMARY_2_ID}" "${EVENT_SUMMARY_2_TIME}" "${EVENT_SUMMARY_2_TYPE}" "${EVENT_SUMMARY_2_SEVERITY}" "${EVENT_SUMMARY_2_STRING}" "${EVENT_SUMMARY_3_ID}" "${EVENT_SUMMARY_3_TIME}" "${EVENT_SUMMARY_3_TYPE}" "${EVENT_SUMMARY_3_SEVERITY}" "${EVENT_SUMMARY_3_STRING}" "${EVENT_SUMMARY_4_ID}" "${EVENT_SUMMARY_4_TIME}" "${EVENT_SUMMARY_4_TYPE}" "${EVENT_SUMMARY_4_SEVERITY}" "${EVENT_SUMMARY_4_STRING}" "${DEEP_LINK_URL}" "${ACCOUNT_NAME}" "${ACCOUNT_ID}"


echo ${EVENT_DETAIL}