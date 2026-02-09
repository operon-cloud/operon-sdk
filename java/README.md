# Operon Java SDK

Enterprise-grade Java client for [Operon.Cloud](https://www.operon.cloud).
Targets Java 17+ and is aligned with Go SDK `v1.3.0`.

## Install

```xml
<dependency>
  <groupId>cloud.operon</groupId>
  <artifactId>operon-sdk</artifactId>
  <version>1.3.0</version>
</dependency>
```

Gradle (Kotlin DSL):

```kotlin
dependencies {
  implementation("cloud.operon:operon-sdk:1.3.0")
}
```

## Quick Start

```java
import cloud.operon.sdk.*;

Config config = Config.builder()
    .clientId(System.getenv("OPERON_CLIENT_ID"))
    .clientSecret(System.getenv("OPERON_CLIENT_SECRET"))
    .build();

try (OperonClient client = new OperonClient(config)) {
    client.init();

    TransactionRequest request = TransactionRequest.builder()
        .correlationId("corr-123")
        .interactionId("int-abc")
        .payload("{\"foo\":\"bar\"}")
        .build();

    Transaction txn = client.submitTransaction(request);
    System.out.println("transaction=" + txn.id());
}
```

Security note: payload bytes are hashed locally (SHA-256) and only `payloadHash` is sent.

## API Surface

- Transaction submit with self-sign or manual-sign
- Full transaction parity fields (state, ROI compatibility fields, actor/assignee attribution)
- Reference cache via `/v1/interactions` and `/v1/participants`
- Workstream APIs:
  - `getWorkstream`
  - `getWorkstreamInteractions`
  - `getWorkstreamParticipants`
- Signature utilities:
  - `generateSignatureHeaders`
  - `validateSignatureHeaders`
- PAT helpers (`PatHelpers`):
  - `signHashWithPAT`, `submitTransactionWithPAT`, `validateSignatureWithPAT`
  - `fetchWorkstream`, `fetchWorkstreamInteractions`, `fetchWorkstreamParticipants`
- Session validation helper:
  - `SessionValidator.validateSession`

## Optional Heartbeat

```java
Config config = Config.builder()
    .clientId("client")
    .clientSecret("secret")
    .sessionHeartbeatInterval(Duration.ofMinutes(2))
    .build();
```

When enabled, the SDK pings `/v1/session/heartbeat` and forces token refresh on `401`.

## Build and Test

```bash
mvn -f java/pom.xml clean test
```
