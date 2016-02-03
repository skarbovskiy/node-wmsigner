#Port of C++ WMSigner module for Node.JS

## Installation

Use npm:

```
$ npm install node-wmsigner
```


## Usage

```
var wmsigner = require('node-wmsigner');

var sign = wmsigner.sign(<wmid>, <password>, <file system path to kwm file>, <string to sign>);
```
