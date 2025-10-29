# Operon Java SDK

Enterprise‑grade Java client for the [Operon.Cloud](https://www.operon.cloud) platform. The SDK targets Java 17+ (tested on JDK 17 and 21) and is packaged with Maven.

## Install

Use the Maven coordinates once the artifact is published (example coordinates shown):

```xml
<dependency>
  <groupId>com.operoncloud</groupId>
  <artifactId>operon-sdk</artifactId>
  <version>1.0.0</version>
  <scope>compile</scope>
</dependency>
```

Gradle (Kotlin DSL):

```kotlin
dependencies {
  implementation("com.operoncloud:operon-sdk:1.0.0")
}
```

During local development (from the repo root):

```bash
mvn -f java/pom.xml -DskipTests=false clean verify
```

## Quick Start

```java
import com.operoncloud.sdk.*;

public class Example {
  public static void main(String[] args) throws Exception {
    Config config = Config.builder()
        .clientId(System.getenv("OPERON_CLIENT_ID"))
        .clientSecret(System.getenv("OPERON_CLIENT_SECRET"))
        .build();

    OperonClient client = new OperonClient(config);
    client.init();

    TransactionRequest request = TransactionRequest.builder()
        .correlationId("corr-123")
        .interactionId("int-abc")
        .payload("{\"foo\":\"bar\"}")
        .build();

    Transaction txn = client.submitTransaction(request);
    System.out.println("transaction=" + txn.getId());
  }
}
```

## Features

- Client‑credentials token provider with proactive refresh
- Interaction/participant catalogue caching
- Optional self‑sign workflow for payload hashes
- Strongly typed models and unit tests

## Requirements

- Java 17 or 21 (LTS)
- Maven 3.9+

—

Looking for more? Visit the Operon.Cloud Developers hub: https://www.operon.cloud/developers
