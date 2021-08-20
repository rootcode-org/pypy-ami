# PyPy-AMI

Create an AMI with Amazon Linux 2 and PyPy

```
pypy-ami.py list                                 List machine images in all regions
pypy-ami.py build server|desktop <description>   Build machine images in all regions
pypy-ami.py delete <identifiers...>              Delete specified machine image(s)

where,
server         Build a server image  
desktop        Build a desktop image (same as server but with addition of MATE desktop, VNCServer and PyCharm)  
<description>  Description for generated image(s)  
<identifier>   Identifiers of images to delete  
```

Regions and other parameters are specified in the CONFIGURATION dictionary  
AWS credentials should be provided locally in the same way as for Boto3  


enjoy!  
 
frankie@rootcode.org
