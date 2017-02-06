This is the System Configuration Access Layer (scal) for LEDE/OpenWrt

It provides a high level abstraction API to access data models defined via
plugins. Multiple plugins are permitted to provide objects belonging to the
same data model, or even extend parameters of the same objects.

This is intended to be used for implementing TR-069, NETCONF and other remote
management protocols, or even provide an abstraction for a CLI running on
a router itself.

== Compiling/Installing SCAL ==

To compile SCAL, use these commands:

cmake .
make

To install:

make install


== ubus API ==

Object: scald
  - status:
    Query the status of the scal daemon.
    Returns a list of data models, and for each model a list of plugins that
    implement it.

    Example: { "models": { "tr-181": { "plugins": [ "example" ] } } }


Object: scald.<datamodel>
  All methods that refer to an object (or an object path) take a string array
  "path", describing the path to the object.
  Example: [ "Device", "ManagementServer" ]
  (equal to Device.ManagementServer in TR-181)

  - list:
    List all objects on the next level below the object specified by the path
    If the path is empty, the root object is listed.
    Example: ubus call scald.tr-181 list '{ "path": [ "Device" ] }'
    returns: { "objects": [ "ManagementServer" ] }

  - info:
    Returns information about an object, including its list of parameters
    Example: ubus call scald.tr-181 info '{ "path": [ "Device", "ManagementServer" ] }'
    returns: { "parameters": { "Password": { "readonly": false }, "Username": { "readonly": false } } }

  - get:
    Reads the value of an object parameter.
    Parameter name is provided as a string in the "name" attribute
    Example: ubus call scald.tr-181 get '{ "path": [ "Device", "ManagementServer" ], "name": "Username" }'
    returns: { "value": "foo" }

  - set:
    Sets an object parameter to a new value
    Parameter name is provided as a string in the "name" attribute, the value
    is provided as a string in the "value" attribute
    Example: ubus call scald.tr-181 set '{"path": [ "Device", "ManagementServer" ], "name": "Username", "value": "baz" }'


Object: scald.acl
  This object is used to allow an external daemon to perform ACL checks for
  incoming requests. After subscribing to this object, the ACL daemon receives
  requests as notifications. If the ACL daemon returns a non-zero status code,
  the incoming request will be refused.
  Example message:
    {"method":"list","plugin":"json","ubus":{"user":"root","group":"wheel"},"path":["DeviceInfo"]}

  Plugins can add arbitrary data to this message to allow ACL filtering to be
  done both before and after data model translation.

  - method:
    Name of the ubus method called on scald.<datamodel>
  - plugin:
    Name of the plugin providing the object/parameter being accessed
  - ubus:
    ACL data from the ubus client that issued the request
  - path:
    Path to the object
  - param:
    Name of the requested parameter
