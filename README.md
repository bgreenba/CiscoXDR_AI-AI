# CiscoXDR_AI-AI
Cisco XDR AI Assisted Investigations **(DEVNET-2387 at Cisco Live US 2025)**

## What does it do?
This project allows you to add functionality to XDR that will 
- provide the capability for you to enter your own custom reference links to observables in the pivot menu (stage 1)
- provide the ability to have those lookups done for you and the results parsed and displayed in the pivot menu without you having to click on them (stage 2)
- provide the ability, when responding to an incident, to send those parsed reference lookup results for all observables in the incident, to a generative AI engine for analysis and guidance (the workflow)

## Included files: 
|file|description|
|---|---|
|AIAI-moduleType.json|The ModuleType specification to use either server below in XDR| 
|app-stage1-pivotrefs.py|A simple reference server that provides links for observable lookups|
|references.py|The list of reference pivots and details that are used by stage1 above|
|app-stage2-prefetchers.py|A reference server that creates the lookup link and then fetches, parses, and returns the content|
|AIAI - [Analyze Incident Observables Metadata] Workflow.json|The workflow that takes the lookup results from stage 2 and creates the worklog entry then submits them to the AI engine|

## Deployment Instructions
1. Deploy the web application of your choice (or both) on a webserver. These were developed on and for Apache2 running [mod_wsgi](https://pypi.org/project/mod-wsgi/) and the [Flask](https://flask.palletsprojects.com/en/stable/) framework.  YMMV on anytihng else.
2. Upload the AIAI-moduleType.json file contents as a POST to the https://visibility.amp.cisco.com/iroh/iroh-int/module-type API endpoint (or regional equivalent) to put the module in your private catalog.
3. Find the integration in your catalog and click the + button to open the installation and configuration page
4. Follow the instructions on that page; basically input the URL at which you installed the code in step 1 and click 'save'.
5. If the healthcheck passes, you are good to go! Go do an investigation or view an incident and see the new options in the pivot menu on observables. IF it failed, troubleshoot and restart :)
6. In XDR Automate, import the workflow for use in Incident Response. 

## Adding Custom Entries in references.py for stage 1

The `references.py` file allows you to define custom entries for observables. Each entry in the list should be a JSON dict with the following structure:

```json
{
  "title": "<Title of the entry>",
  "description": "<Description of the entry>",
  "url": "<Base URL for the entry>",
  "type": ["<Type of observable>, <another type of observable>"],
  "id-string": "<the identification string prefix that XDR will use to handle this specific reference link in the menu">
}
```

### Fields Description:
- `title`: A string representing the title of the entry.
- `description`: A string describing the purpose of the entry.
- `url`: The base URL to be used for the entry. The observable's value will be appended to this URL.
- `type`: A list of observable types that this entry applies to. Use `"all"` to apply to all types.
- `id-string`:  A unique identifier prefix for this response object, that is used to track each of the responses. To this string, the server will append the observable type and the observable value to make it unique to the investigation.

### Variables:
In the description and url fields, you can use `{obs_type}` to refer to the observable type, and `{obs_value}` to refer to the observable value. For example, if for an investigation of the IP _1.2.3.4_ you want to return a link like `http://iplookup.foo/ip/1.2.3.4` and from the same reference source a lookup for the domain _bad.biz_ should be `https://iplookup.foo/domain/bad.biz`, then the string for the url field should be `https://iplookup.biz/{obs_type}/{obs_value}`

### Available Types:

Observable types are not prescribed or limited; anything goes. However, the following observable types are broadly supported by XDR integrations, in addition to this server's "all" wildcard:

- `ip`
- `domain`
- `sha1`
- `sha256`
- `md5`
- `hostname`
- `url`
- `email`
- `mac_address`
 
## Adding Custom Entries in references.py for stage 2
The stage 2 app offers the choice of having the reference results be fetched and parsed, or simply linked to in the menu. 
- To have the link appear in the menu only, use the same format as above to create entries in the `custom_pivots` list.
- To have the link be fetched by the server and parsed to create the menu items dynamically, write a function to do so (eg `get_certificate_info()`) and then call that function from the appropriate observable type's `if` statement in `refer_observables()`. If there isn't an `if` statement for the desired observable type, simply add one. 

## Contributors:
- Matthew Franks
- Christopher Van Der Made
- Brandon Macer
- Matt Vander Horst
- Ben Greenbaum
