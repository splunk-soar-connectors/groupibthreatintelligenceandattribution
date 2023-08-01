[comment]: # "Auto-generated SOAR connector documentation"
# Group IB Threat Intelligence

Publisher: Group-IB  
Connector Version: 1.0.5  
Product Vendor: Group-IB  
Product Name: Threat Intelligence  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.4.0  

This app ingests incidents and IOCs from Group-IB Threat Intelligence

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
**api_key** |  required  | password | API key
**base_url** |  required  | string | Group-IB API URL
**insecure** |  optional  | boolean | Verify server certificate
**compromised_account** |  optional  | boolean | Ingest incidents from compromised/account collection
**compromised_account_start** |  optional  | string | Date to start
**compromised_breached** |  optional  | boolean | Ingest incidents from compromised/breached collection
**compromised_breached_start** |  optional  | string | Date to start
**compromised_card** |  optional  | boolean | Ingest incidents from compromised/card collection
**compromised_card_start** |  optional  | string | Date to start
**bp_phishing** |  optional  | boolean | Ingest incidents from bp/phishing collection
**bp_phishing_start** |  optional  | string | Date to start
**bp_phishing_kit** |  optional  | boolean | Ingest incidents from bp/phishing_kit collection
**bp_phishing_kit_start** |  optional  | string | Date to start
**osi_git_leak** |  optional  | boolean | Ingest incidents from osi/git_leak collection
**osi_git_leak_start** |  optional  | string | Date to start
**osi_public_leak** |  optional  | boolean | Ingest incidents from osi/public_leak collection
**osi_public_leak_start** |  optional  | string | Date to start
**malware_targeted_malware** |  optional  | boolean | Ingest incidents from malware/targeted_malware collection
**malware_targeted_malware_start** |  optional  | string | Date to start

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[on poll](#action-on-poll) - Callback action for the on_poll ingest functionality  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

This action make a simple API request to Group-IB with provided credentials to validate them.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'on poll'
Callback action for the on_poll ingest functionality

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container_id** |  optional  | The parameter isn't used in this app | string | 
**start_time** |  optional  | Start of time range, in epoch time (milliseconds) | numeric | 
**end_time** |  optional  | End of time range, in epoch time (milliseconds) | numeric | 
**container_count** |  optional  | Maximum number of container records to query for | numeric | 
**artifact_count** |  optional  | Maximum number of artifact records to query for | numeric | 

#### Action Output
No Output