[comment]: # "Auto-generated SOAR connector documentation"
# Group IB Threat Intelligence

Publisher: Group\-IB  
Connector Version: 1\.0\.4  
Product Vendor: Group\-IB  
Product Name: Threat Intelligence  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.4\.0  

This app ingests incidents and IOCs from Group\-IB Threat Intelligence

[comment]: # "File: README.md"
[comment]: # ""
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Asset configuration

1). Find **Group IB Threat Intelligence** app, click **CONFIGURE NEW ASSET** button, in **Asset
Settings** tab enter your credentials and configure necessary collections.

-   **Group-IB API URL** is https://tap.group-ib.com/api/v2/
-   **Username** is the login for the Group-IB TI portal.
-   **Verify server certificate** - Whether to allow connections without verifying SSL certificates
    validity.
-   **API key** can be manually generated in the portal:  
    The old version of the portal: log in to the TI -> click on your name in the right upper corner
    -> choose the **Profile** option -> click on the **Go to my setting** button under your name ->
    under the **Change password** button you will see **API KEY generator** . **Do not forget to
    save the API key** .  
    The new version of the portal: log in to the TI -> click on your name in the right upper corner
    -> choose the **Profile** option -> click on **Security and Access** tab -> click on **Personal
    token** tab -> click on **Generate new token** button -> enter your password, copy token and
    click **Save** button.
-   Every collection has a poll starting date and enable checkbox.

2). If you are using a proxy to connect to the Group IB TI server, you can specify the appropriate
settings. You need to expand the **Advanced** section on the bottom, find the **Environment**
section and click **+ Variable** . **NAME** must be HTTPS_PROXY, **VALUE** is your proxy server.

3). In the **Ingest settings** tab choose the polling interval you need.

## SDK and SDK Licensing details for the app

#### pytia

This app uses the pytia module, which is licensed under the MIT License (MIT), Copyright (c) 2023
Group-IB.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Threat Intelligence asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**username** |  required  | string | Username
**api\_key** |  required  | password | API key
**base\_url** |  required  | string | Group\-IB API URL
**insecure** |  optional  | boolean | Verify server certificate
**compromised\_account** |  optional  | boolean | Ingest incidents from compromised/account collection
**compromised\_account\_start** |  optional  | string | Date to start
**compromised\_breached** |  optional  | boolean | Ingest incidents from compromised/breached collection
**compromised\_breached\_start** |  optional  | string | Date to start
**compromised\_card** |  optional  | boolean | Ingest incidents from compromised/card collection
**compromised\_card\_start** |  optional  | string | Date to start
**bp\_phishing** |  optional  | boolean | Ingest incidents from bp/phishing collection
**bp\_phishing\_start** |  optional  | string | Date to start
**bp\_phishing\_kit** |  optional  | boolean | Ingest incidents from bp/phishing\_kit collection
**bp\_phishing\_kit\_start** |  optional  | string | Date to start
**osi\_git\_leak** |  optional  | boolean | Ingest incidents from osi/git\_leak collection
**osi\_git\_leak\_start** |  optional  | string | Date to start
**osi\_public\_leak** |  optional  | boolean | Ingest incidents from osi/public\_leak collection
**osi\_public\_leak\_start** |  optional  | string | Date to start
**malware\_targeted\_malware** |  optional  | boolean | Ingest incidents from malware/targeted\_malware collection
**malware\_targeted\_malware\_start** |  optional  | string | Date to start

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[on poll](#action-on-poll) - Callback action for the on\_poll ingest functionality  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

This action make a simple API request to Group\-IB with provided credentials to validate them\.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'on poll'
Callback action for the on\_poll ingest functionality

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_id** |  optional  | The parameter isn't used in this app | string | 
**start\_time** |  optional  | Start of time range, in epoch time \(milliseconds\) | numeric | 
**end\_time** |  optional  | End of time range, in epoch time \(milliseconds\) | numeric | 
**container\_count** |  optional  | Maximum number of container records to query for | numeric | 
**artifact\_count** |  optional  | Maximum number of artifact records to query for | numeric | 

#### Action Output
No Output