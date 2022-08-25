# Net LineDancer Framework

This is a framework that connects to the API of LogicVein Net LineDancer monitoring software.

## Authentication

Credentials are stored in JSON format, in the same directory as the `nld.py` file. The name of the file should be `credentials.json`.

Other authentication methods, such as KDBX, have been tested, but this way it keeps the hard-coded passwords out of the source code.

```
{
	"credentials": {
		"username": "",
		"password": "",
		"token": ""
	}
}
```

API calls will automatically authenticate on instantiation and a token will be generated for subsequent API calls.

## Getting Started

To instantiate a `NetLineDancer` object, pass a string of the server name :

```
>>> server_name = 'nld01.domain.com'
>>> n = NetLineDancer(server)
```

Then, to retrieve all inventory on the appliance :

```
>>> inventory = n.get_inventory_all()
```

## ThousandEyes Features

Most features of the API to retrieve data are written :
- Get all inventory
- Get device inventory
- Get managed networks by name
- Get managed networks by bridge name
- Get all managed networks
- Get all managed network names
- Get jumphost by network name
- Get configuration log history
- Get single configuration
- Print configuration file
- Get credential configuration
- Get a credential set
- Run a scheduler job
- Get a scheduled job information
- Get all scheduled job information
- Get plugin details
- Get compliance rules
- Get all compliance policies
- Get a compliance policy
- Get compliance violations by IP
- Get compliance violations by policy name
- Get telemetry ARP tables
- Get a telemetry ARP entry
- Get all telemetry ARP entries
- Get telemetry MAC table
- Get telemetry neighbors
- Get telemetry port
- Get a terminal session token
- Get a terminal session log
- Get all bridges
- Get a bridge information