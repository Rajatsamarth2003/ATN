
# P4 Tutorials Setup & Execution Guide

## VM Setup (VirtualBox and Vagrant)

### 1. Install Prerequisites

* Install Vagrant
* Install VirtualBox

---

### 2. Clone Repository

```bash
git clone https://github.com/p4lang/tutorials
cd tutorials
```

---

### 3. Choose VM Version

Navigate to a VM folder:

```bash
cd vm-ubuntu-24.04
```

If issues occur, try:

```bash
cd vm-ubuntu-20.04
```

---

### 4. Start VM

```bash
vagrant up
```

---

### 5. Login Credentials

* Username: `p4`
* Password: `p4`

---

## Inside the VM

Run the following:

```bash
git clone https://github.com/p4lang/tutorials
mkdir src
cd src
../tutorials/vm-ubuntu-24.04/install.sh |& tee log.txt
```

---

## Installation Notes

* Installation time may be around 5 hours
* Ensure stable internet connection
* Keep system powered throughout

---

## Performance Optimization

* Set VirtualBox process priority to High using Task Manager
* Reduce VM display resolution
* Enable performance mode in system settings

---

## Cleanup Script (Optional)

A `clean.sh` script is available.

Use carefully as it may remove important files. Only use if you are prepared to reinstall if needed.

---

## Verify Installation

Test using the basic example:

```bash
cd ~/tutorials/exercises/basic
make run
```

If this runs successfully, the setup is complete.

---

## Troubleshooting

* Dependency issues may arise
* Resolve by installing missing packages and checking logs
* Use documentation or external help if needed

---

## Folder Placement

1. Navigate to:
```

~/tutorials/exercises/

````

2. Create a new directory:
```bash
mkdir <your-folder-name>
````

3. Copy all project files into this directory.

4. Use the `nano` editor while copying file contents to preserve indentation:

   ```bash
   nano filename
   ```

---

## Build and Run Steps

Run the following commands in order:

```bash
make build
sudo mn -c
make run
```

This will:

* Build the P4 program
* Clean Mininet
* Start the topology

---

## Final Steps for walkthrough of our project

* Copy our project files into the correct directory
* Run build and execution commands
* Refer to our report for project-specific details

---

## Summary

* Set up VM using Vagrant
* Install required dependencies
* Verify setup with basic example
* Resolve any issues
* Execute your project

## Disclaimer

This material is developed strictly for educational purposes as part of academic learning. It is not intended for production use or deployment in real-world systems without proper validation, testing, and security considerations.

## Note on Report Usage

The report associated with this project was created specifically for academic evaluation purposes.

It is recommended to first go through this README, as it contains the most useful and practical information required to understand and implement the project. The content in the README is written in a generic manner and can be applied to a wide range of P4-based projects.

After reviewing the README, you may refer to the report for additional details and context.

## Tip

You can always refer to the tutorial files provided in the P4 repository. These files can also be given to AI tools as context while working on your project. Treat them as guidelines so that the AI generates code that follows correct P4 syntax and structure.

In some cases, AI may generate additional files such as `.py` scripts for topology or controllers. However, for simple projects, these are usually not required. It is better to follow the approach used in the tutorials and work with JSON configuration files for defining runtime behavior.


