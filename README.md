# ACG-SecureCam [![Build Status](https://travis-ci.com/Infinitide/ACG-SecureCam.svg?token=VjEYc68MUWgPSpWqgDNV&branch=master)](https://travis-ci.com/Infinitide/ACG-SecureCam)

Server and Client program to be used to retrieve information from WebCam

## Dependencies
- Apache Commons CLI
- Bouncy Castle

## Compiling the program from source
Source file can be found at [src](src)

### Server
In the [server src directory](src/Server) run the following command
```
javac -cp ../lib/*;. Server.java
```

### Client
In the [Client src directory](src/Client) run the following command
```
javac -cp ../lib/*;. Client.java
```

## Prerequisites

### Server
Ensure that the Certificate Authority's cert is in the Server's Directory [ca.crt](dist/Server/ca.crt)
Ensure that a keystore (in PKCS#12 format) with the Server's private certificate in the Server's directory [dist/Server/securecam.server.pkcs12](dist/Server/securecam.server.pkcs12)

### Client
Ensure that the Certificate Authority's cert is in the Client Directory [ca.crt](dist/Client/ca.crt)
Ensure that a keystore (in PKCS#12 format) with the Client's private certificate in the Client's directory [dist/Client/securecam.client.pkcs12](dist/Client/securecam.client.pkcs12)

## Using the Program
Compiled program with its relevant files can be found in [dist](dist)

### Server
Run the following command in the directory which contains the compiled server program
```
java -jar Server.jar
```

#### CLI Options

```
usage: java -jar Server.jar <options>
 -a,--alias <arg>                Alias for cert in keystore
 -ap,--alias-password <arg>      Alias Password for alias
 -c,--certificate <arg>          Certificate
 -h,--help                       Prints help message
 -kp,--keystore-password <arg>   Key Store Password
 -ks,--keystore <arg>            Key Store Path
 -l,--listen <arg>               Address which server listens on
 -p,--port <arg>                 Port which server listens on
 -v,--verbose                    Verbose Output
```

### Client
Run the following command in the directory which contains the compiled server program
```
java -jar Client.jar
```

#### CLI Options
```
usage: java -jar Client.jar <options>
 -a,--alias <arg>                Alias for cert in keystore
 -ap,--alias-password <arg>      Alias Password for alias
 -c,--certificate <arg>          Certificate
 -g,--gui                        Starts Client GUI
 -h,--help                       Prints help message
 -kp,--keystore-password <arg>   Key Store Password
 -ks,--keystore <arg>            Key Store Path
 -o,--output <arg>               File to save image to
 -p,--port <arg>                 Port which server listens on
 -s,--server <arg>               Address which server listens on
 -v,--verbose                    Verbose Output
```