# SeeYouLetter Backend
[![Coverage Status](https://coveralls.io/repos/github/seeyouletter/seeyouletter-be/badge.svg?branch=main)](https://coveralls.io/github/seeyouletter/seeyouletter-be?branch=main)

___

# Overview

## Requirements
* `java`
* `docker`
* `gradle`

## Build
```shell
./gradlew clean build
```

## Running

### 애플리케이션 실행에 필요한 컨테이너 생성
```shell
docker-compose -f docker/docker-compose-local.yml up -d
```

### 애플리케이션 실행
```shell
./gradlew clean bootRun
```
