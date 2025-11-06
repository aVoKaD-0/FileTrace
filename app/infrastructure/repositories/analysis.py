import os

cwd = os.getcwd().replace('\\', '\\\\')

hyper = "D:\\programming\\GIt\\gitlab\\antivirus\\Hyper-v"
docker = f"{cwd}\\dockerer"
docker2 = "D:\\\\programming\\\\GIt\\\\gitlab\\\\antivirus2\\\\dockerer"

os.path.join(docker, "files")
os.path.join(docker, "analysis")

os.path.join(hyper, "dock", "Virtual Hard Disks")
os.path.join(hyper, "dock", "Virtual Machines")
os.path.join(hyper, "dock", "Snapshots")
os.path.join(hyper, "files")
os.path.join(hyper, "results")
os.path.join(hyper, "temporary_disks")
os.path.join(hyper, "analysis_VMs")

# Структура
# Hyper
#     dock
#         Virtual Hard Disks
#         Virtual Machines
#         Snapshots
#     files
#     results
#     temporary_disks
#     analysis_VMs
