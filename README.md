# PyPy-AMI

Create an AMI with Amazon Linux 2 and PyPy

```
pypy-ami.py list                   List machine images
pypy-ami.py build server|desktop   Build machine images
pypy-ami.py delete <ami_id...>     Delete machine image(s)

where,
  server     Build a server image
  desktop    Build a desktop image (same as server but with addition of MATE desktop)
  config     Optional, path to configuration file; if not specified then config is loaded from current folder
  <ami_id>   AMI identifier
```

AWS credentials should be provided locally in the same way as for Boto3  

enjoy!  
 
frankie@rootcode.org
