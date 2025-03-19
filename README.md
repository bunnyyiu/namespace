# A simple program used to study Linux namespace and cgroup.
ref : http://coolshell.cn/articles/17010.html

* To compile
~~~
gcc container.c -o container -luuid
~~~

* To build rootfs
~~~
./buildRootfs.sh
~~~

* To create COW image
~~~
mkdir upper workdir containerRoot
sudo mount -t overlay overlay -olowerdir=rootfs,upperdir=upper,workdir=workdir containerRoot
~~~

* To create a shared home directory to container
~~~
mkdir homeShare
cd homeShare;touch a_shared_file
~~~

* To run
~~~
sudo ./container -f containerRoot -c /bin/bash -v homeShare:home -u root:root -h container
~~~
