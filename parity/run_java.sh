#!/bin/sh
# usage: run_java.sh <requests.jsonl> <out>
# Compiles the probe against the Maven build and runs it on JSON-lines requests.
# Prerequisite (repo root): mvn -q package -DskipTests && mvn -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt
set -e
cd "$(dirname "$0")"
if [ -f ../env.sh ]; then . ../env.sh; CLASSPATH_DEPS="$CP:../stubs/classes"; else CLASSPATH_DEPS="$(cat ../target/cp.txt)"; fi
mkdir -p java/classes
javac -nowarn -cp "../target/classes:$CLASSPATH_DEPS" -d java/classes java/ParityProbe.java java/ApiParity.java 2>&1 | grep -v "^Note:" || true
java -Dcfg=../config -cp "../target/classes:$CLASSPATH_DEPS:java/classes" ParityProbe < "$1" > "$2"
