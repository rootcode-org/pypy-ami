# Copyright is waived. No warranty is provided. Unrestricted use and modification is permitted.

import os
import sys
import tempfile
import random
import string
import time
import datetime
import subprocess
from urllib.request import urlopen

if "_install" not in sys.argv:
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        sys.exit("Requires Boto3 module; try 'pip install boto3'")

    try:
        import paramiko
    except ImportError:
        sys.exit("Requires Paramiko module; try 'pip install paramiko'")

PURPOSE = """\
pypy-ami.py list                                   List machine images in all regions
pypy-ami.py build server|desktop [<description>]   Build machine images in all regions
pypy-ami.py delete <identifiers...>                Delete specified machine image(s)

where,
  server         Build a server image
  desktop        Build a desktop image (same as server but with addition of MATE desktop)
  <description>  Optional: Description for generated image(s) 
  <identifier>   Identifiers of images to delete
"""

CONFIGURATION = {
    "pypy_version": "pypy3.6-v7.3.3",            # install this version of pypy to image
    "pycharm_version": "2021.2.2",               # install this version of pycharm when creating desktop image
    "source_ami": {
        "us-west-2": "ami-013a129d325529d4d",
        "eu-west-2": "ami-02f5781cba46a5e8a"
    }
}


def list_images(regions):
    all_images = {}
    for region in regions:
        client = boto3.client('ec2', config=Config(region_name=region))
        response = client.describe_images(Owners=['self'])
        images = response['Images']
        images.sort(key=lambda x: x['CreationDate'])
        all_images[region] = images
    return all_images


def build_image(region, build_type, description):

    print('Creating ' + build_type + ' AMI in ' + region)
    client = boto3.client('ec2', config=Config(region_name=region))

    # Find an available subnet
    print(' finding subnet...')
    subnet_id = vpc_id = None
    response=client.describe_subnets()
    for subnet in response['Subnets']:
        if subnet['State'] == 'available' and subnet['AvailableIpAddressCount'] > 0:
            subnet_id = subnet['SubnetId']
            vpc_id = subnet['VpcId']
            break
    if subnet_id is None:
        sys.exit('Unable to find an available subnet')

    # Create a temporary keypair
    print(' creating temporary keypair...')
    temporary_name = '_imagebuilder_' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    response = client.create_key_pair(KeyName=temporary_name)
    keypair_material = response["KeyMaterial"]
    keypair_id = response["KeyPairId"]
    keypair_file_path = os.path.join(tempfile.gettempdir(), ''.join(random.choices(string.ascii_uppercase + string.digits, k=20)))
    with open(keypair_file_path, "w") as f:
        f.write(keypair_material)

    # Create a temporary security group that allows SSH access from this WAN IP only
    print(' creating temporary security group...')
    response = client.create_security_group(
        Description='temporary security group for image builder',
        GroupName=temporary_name,
        VpcId=vpc_id
    )
    secgrp_id = response['GroupId']
    wan_ip = urlopen('https://checkip.amazonaws.com').read().strip().decode('utf8')
    response = client.authorize_security_group_ingress(
        GroupId=secgrp_id,
        CidrIp=wan_ip + '/32',
        FromPort=22,
        ToPort=22,
        IpProtocol='tcp'
    )

    # Launch instance
    print(' launching builder instance...')
    source_ami = CONFIGURATION["source_ami"][region]
    response = client.run_instances(
        ImageId=source_ami,
        InstanceType='c5.xlarge',
        KeyName=temporary_name,
        MaxCount=1,
        MinCount=1,
        NetworkInterfaces=[
            {
                'AssociatePublicIpAddress': True,
                'DeviceIndex': 0,
                'SubnetId': subnet_id,
                'Groups': [secgrp_id],
            }
        ],
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [{'Key': 'Name', 'Value': temporary_name,},],
            },
        ],
    )
    instance_id=response['Instances'][0]['InstanceId']

    # Wait for instance to be ready
    print(' waiting for SSH...')
    status = None
    while status != 'running':
        time.sleep(5)
        response = client.describe_instance_status(InstanceIds=[instance_id], IncludeAllInstances=True)
        status = response['InstanceStatuses'][0]['InstanceState']['Name']
    time.sleep(60)      # more time needed for SSH to be ready

    # Get instance public ip
    response = client.describe_instances(InstanceIds=[instance_id])
    instance_ip_address=response['Reservations'][0]['Instances'][0]['PublicIpAddress']

    # Connect to instance
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(instance_ip_address, username='ec2-user', key_filename=keypair_file_path)
    sftp = ssh.open_sftp()

    # Upload this script
    print(' uploading configuration script...')
    local_script_path = sys.argv[0]
    remote_script_name = os.path.basename(sys.argv[0])
    sftp.put(local_script_path, remote_script_name)
    sftp.chmod(remote_script_name, 0o744)

    # Execute script
    print(' executing configuration script...')
    stdin, stdout, stderr = ssh.exec_command('sudo python3 ' + remote_script_name + ' _install ' + build_type)
    exit_status = stdout.channel.recv_exit_status()
    sftp.remove(remote_script_name)

    # Remove temporary key from instance
    sftp.remove('.ssh/authorized_keys')

    # Disconnect from instance
    sftp.close()
    ssh.close()

    # Stop instance
    print(' stopping builder instance...')
    response = client.stop_instances(InstanceIds=[instance_id])
    state = None
    while state != 'stopped':
        time.sleep(5)
        response = client.describe_instance_status(InstanceIds=[instance_id], IncludeAllInstances=True)
        state = response['InstanceStatuses'][0]['InstanceState']['Name']

    # Generate AMI from instance
    print(' generating AMI...')
    now = datetime.datetime.utcnow()
    ami_name = 'amzn2-' + build_type + '-{0}{1:>02}{2:>02}-{3:>02}{4:>02}{5:>02}'.format(str(now.year)[-2:], now.month, now.day, now.hour, now.minute, now.second)
    response = client.create_image(
        Description=description,
        InstanceId=instance_id,
        Name=ami_name
    )
    image_id = response['ImageId']

    # Wait for AMI generation to complete
    state = None
    snapshot_id = None
    while state != 'available':
        time.sleep(15)
        response = client.describe_images(ImageIds=[image_id])
        state = response['Images'][0]['State']
        snapshot_id = response['Images'][0]['BlockDeviceMappings'][0]['Ebs']['SnapshotId']

    # Tag associated snapshot
    print(' tagging snapshot...')
    response = client.create_tags(Resources=[snapshot_id], Tags=[{'Key': 'Name', 'Value': ami_name}])

    # Terminate instance
    print(' terminating builder instance...')
    response = client.terminate_instances(InstanceIds=[instance_id])

    # Wait for instance to be terminated
    status = None
    while status != 'terminated':
        time.sleep(5)
        response = client.describe_instance_status(InstanceIds=[instance_id], IncludeAllInstances=True)
        if response['InstanceStatuses']:
            status = response['InstanceStatuses'][0]['InstanceState']['Name']

    # Delete temporary security group
    print(' deleting temporary security group...')
    response = client.delete_security_group(GroupId=secgrp_id)

    # Delete temporary keypair
    print(' deleting temporary keypair...')
    response = client.delete_key_pair(KeyPairId=keypair_id)
    os.remove(keypair_file_path)

    print(' done\n')


def delete_image(region, image):
    client = boto3.client('ec2', config=Config(region_name=region))
    # Delete image
    identifier = image["ImageId"]
    client.deregister_image(ImageId=identifier)
    print("deleted {0} from {1}".format(identifier, region))
    # Delete associated snapshot
    device_mappings = image["BlockDeviceMappings"]
    for mapping in device_mappings:
        if "Ebs" in mapping:
            snapshot_id = mapping["Ebs"]["SnapshotId"]
            client.delete_snapshot(SnapshotId=snapshot_id)
            print("deleted {0} from {1}".format(snapshot_id, region))


# executes on builder instance
def install_pypy():
    pypy_distribution = CONFIGURATION['pypy_version'] + "-linux64"
    pypy_file = pypy_distribution + ".tar.bz2"
    pypy_uri = "https://downloads.python.org/pypy/" + pypy_file
    fp = urlopen(pypy_uri)
    with open(pypy_file, "wb") as f:
        f.write(fp.read())
    p = subprocess.Popen(["tar", "xjf", pypy_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    pypy_binary = "/home/ec2-user/" + pypy_distribution + "/bin/pypy3"
    subprocess.call(["ln", "-sf", pypy_binary, "/usr/bin/pypy"])
    os.remove(pypy_file)


# executes on builder instance
def install_desktop():
    pypy_version=CONFIGURATION['pypy_version']
    pycharm_version=CONFIGURATION['pycharm_version']

    # Install and configure desktop
    # see https://aws.amazon.com/premiumsupport/knowledge-center/ec2-linux-2-install-gui/
    subprocess.call(["yum", "-y", "-q", "update"])
    subprocess.call(["amazon-linux-extras", "enable", "mate-desktop1.x"])
    subprocess.call(["yum", "clean", "metadata"])
    subprocess.call(["yum", "-y", "-q", "install", "mesa-dri-drivers", "dejavu-sans-fonts", "dejavu-sans-mono-fonts", "dejavu-serif-fonts", "mate-session-manager", "mate-panel", "marco", "caja", "mate-terminal"])

    # Set the preferred desktop as MATE
    with open(".Xclients", "w") as f:
        f.write("/usr/bin/mate-session")
    os.chmod(".Xclients", 0o775)

    # Install PyCharm IDE
    subprocess.call(["wget", "-q", "https://download.jetbrains.com/python/pycharm-community-" + pycharm_version + ".tar.gz"])
    subprocess.call(["tar", "xzf", "pycharm-community-" + pycharm_version + ".tar.gz"])
    os.remove("pycharm-community-" + pycharm_version + ".tar.gz")

    # Enable ec2-user to bind sockets to ports less than 1024 and to set process priority
    subprocess.call(["setcap cap_net_bind_service,cap_sys_nice=+ep /usr/bin/python2.7"], shell=True)
    subprocess.call(["setcap cap_net_bind_service,cap_sys_nice=+ep /usr/bin/python3.7"], shell=True)
    pypy_path = "/home/ec2-user/" + pypy_version + "-linux64/bin/pypy"
    if pypy_version.find("pypy3") != -1:
        pypy_path += "3"
    subprocess.call(["setcap cap_net_bind_service,cap_sys_nice=+ep " + pypy_path], shell=True)

    # Workaround for setcap causing pypy to execute in secure-execution mode
    # Need to copy libraries that pypy depends on into a trusted path
    subprocess.call(["cp /home/ec2-user/" + pypy_version + "-linux64/bin/libpypy3-c.so /usr/lib64/"], shell=True)
    subprocess.call(["cp /home/ec2-user/" + pypy_version + "-linux64/lib/libtinfow.so.6 /usr/lib64/"], shell=True)

    # Install and configure VNC
    # - allow VNC connection with no password; this is okay because we connect via secure SSH port-forwarding
    subprocess.call(["yum", "-y", "-q", "install", "tigervnc-server"])
    with open("/lib/systemd/system/vncserver@.service", "r") as f:
        lines = f.readlines()
        for i in range(len(lines)):
            lines[i] = lines[i].replace("<USER>", "ec2-user")
    with open("/etc/systemd/system/vncserver@.service", "w") as f:
        f.write("".join(lines))

    with open("/usr/bin/vncserver_wrapper", "r") as f:
        lines = f.readlines()
        for i in range(len(lines)):
            lines[i] = lines[i].replace("/usr/bin/vncserver ${INSTANCE}", "/usr/bin/vncserver ${INSTANCE} -securitytypes none")
    with open("/usr/bin/vncserver_wrapper", "w") as f:
        f.write("".join(lines))

    subprocess.call(["systemctl", "enable", "vncserver@:1"])


# executes on builder instance
def configure_os():
    sysctl_parameters = {
        # Limit use of swap file until absolutely necessary
        "vm.swappiness": 5,                     # Amazon Linux 2 default is 60

        # Maximum allowed connection backlog; set this high to assist with re-connection surges
        "net.core.somaxconn": 65536,           # Amazon Linux 2 default is 128

        # Allow all non-system ports to be used for outbound sockets
        "net.ipv4.ip_local_port_range": "1024 65535",        # Amazon Linux 2 default is 32768 60999
    }

    lines = [key + " = " + str(value) for key, value in sysctl_parameters.items()]
    with open("/etc/sysctl.d/99-server.conf", "w") as f:
        f.write("\n".join(lines))

    # Create 2GB swap file
    subprocess.call(["dd", "if=/dev/zero", "of=/swapfile", "bs=64M", "count=32"])
    os.chmod("/swapfile", 0o600)     # octal value
    subprocess.call(["mkswap", "/swapfile"])
    subprocess.call(["swapon", "/swapfile"])
    with open("/etc/fstab", "a") as f:
        f.write("\n/swapfile swap swap defaults 0 0\n")

    # Configure SSH
    with open("/etc/ssh/sshd_config", "a") as f:
        f.write("\n")
        f.write("UseDNS no\n")                 # Prevent reverse DNS lookup to reduce login time
        f.write("GSSAPIAuthentication no\n")  # Disable GSSAPI lookup to reduce login time
        f.write("PermitRootLogin no\n")       # No reason to ever login as root

    # Remove host keys; this forces each instance launched from the AMI to generate its own unique host keys
    os.remove("/etc/ssh/ssh_host_ecdsa_key")
    os.remove("/etc/ssh/ssh_host_ecdsa_key.pub")
    os.remove("/etc/ssh/ssh_host_ed25519_key")
    os.remove("/etc/ssh/ssh_host_ed25519_key.pub")
    os.remove("/etc/ssh/ssh_host_rsa_key")
    os.remove("/etc/ssh/ssh_host_rsa_key.pub")

    # Disable local root access
    subprocess.call(["sudo", "passwd", "-l", "root"])


# executes on builder instance
def configure_pam():
    # Configure limits for users logged in via PAM
    # Do this configuration last as once executed the shell will become inaccessible until reboot
    with open("/etc/security/limits.conf", "a") as f:
        f.write("\n* hard nofile 1048576")
        f.write("\n* soft nofile 1048576")


if __name__ == '__main__':

    if sys.version_info < (3, 7):
        sys.exit("Python version must be 3.7 or later")
    if len(sys.argv) < 2:
        sys.exit(PURPOSE)

    command = sys.argv[1]
    regions = CONFIGURATION["source_ami"].keys()

    if command == "list":
        for region, images in list_images(regions).items():
            for image in images:
                identifier = image["ImageId"]
                name = image["Name"]
                description = image["Description"] if "Description" in image else ""
                print("{0}  {1:28} {2}    {3}".format(region, name, identifier, description))

    elif command == "build":
        if len(sys.argv) < 3:
            sys.exit("missing parameter(s)")
        build_type = sys.argv[2].lower()
        if build_type not in ['server', 'desktop']:
            sys.exit('Unknown build type')
        description = " ".join(sys.argv[3:])
        for region in regions:
            build_image(region, build_type, description)

    elif command == "delete":
        for region, images in list_images(regions).items():
            for image in images:
                for identifier in sys.argv[2:]:
                    if identifier == image["ImageId"]:
                        delete_image(region, image)
                        break

    elif command == "_install":
        # executes on builder instance
        configuration_type = sys.argv[2]
        if configuration_type == "server":
            install_pypy()
            configure_os()
            configure_pam()
        elif configuration_type == "desktop":
            install_pypy()
            install_desktop()
            configure_os()
            configure_pam()

    else:
        sys.exit("Unknown command")
