#!/bin/bash
OUT=~/evidence_$(date +%Y%m%d_%H%M%S).txt

echo "=== DEVICE POLICY DUMP ===" >> $OUT
adb shell dumpsys device_policy >> $OUT

echo "=== LAFORGE/ORG/ENROLL ===" >> $OUT
adb shell dumpsys device_policy | grep -iE "laforge|organization|admin|enroll|tenant|domain|owner" >> $OUT

echo "=== ACCOUNT LIST ===" >> $OUT
adb shell dumpsys account | grep -iE "account|domain|org|enterprise|work" >> $OUT

echo "=== FIREBASE HIT ===" >> $OUT
curl -s https://com-android-cloud-policy.firebaseio.com/.json >> $OUT

echo "=== DPC PACKAGE PATH ===" >> $OUT
adb shell pm path com.google.android.apps.work.clouddpc >> $OUT

echo "=== PROVISIONING STATE ===" >> $OUT
adb shell dumpsys user | grep -iE "profile|managed|owner|work|restrict" >> $OUT

echo "=== ESIM INFO ===" >> $OUT
adb shell dumpsys euicc_card_mgr >> $OUT

echo "=== ENROLLMENT TOKENS ===" >> $OUT
adb shell dumpsys activity provider com.google.android.apps.work.clouddpc | grep -iE "token|enroll|laforge|org" >> $OUT

echo "=== ZERO TOUCH CHECK ===" >> $OUT
adb shell settings get global device_provisioned >> $OUT
adb shell settings get global enrollment_token >> $OUT
adb shell settings get secure managed_profile_id >> $OUT

echo "=== DONE === OUTPUT AT $OUT"
cat $OUT
