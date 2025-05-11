## Section 8: Secure Ingress

curl -kv  => to see more information about tls certificate

- to create a certificate and a key:

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout cert.key -out cert.crt -subj "/CN=world.universe.mine/O=world.universe.mine"

- to createa secret:

kubectl create secret tls  ingress_secret_name --cert=cert.pem --key=key.pem

- add the secret to ingress manifest

spec:

  tls:

   - hosts:

      - secure-ingress.com ( we should have the same name as th one speified when we created the key an the cert | we have also to add the domain name to /etc/hosts )

     secretName:  ingress_secret_name

 

then retest: curl secure-ingress.com  -kv --resolve ip:port:secure-ingress.com:port

 

to find the ingressClass type: kubernetes get ingressclass

 

## Section 9: Cluster Setup - Node Metadata Protection

=> intro

- in all cloud provider we find a matadata server which virtul machines can connect with  this metadata server to get information (env, service account they use, senstive credentials ....)

- metadata are reacheable by default

- to restrict access to it we have to use network policy

 

=> access metadata

Metada is reachable from pod and Vms

 

=> restrict access

 

=> only pods with label are allowed to access metadata endpoint

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cloud-metadata-allow
  namespace: default
spec:
  podSelector:
    matchLabels:
      role: metadata-accessor
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 169.254.169.254/32

=> restrcit access


# all pods in namespace cannot access metadata endpoint
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cloud-metadata-deny
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0 ( allow all ip adresses except 169.254.169.254/32  )
        except:
        - 169.254.169.254/32   ( the ip of the metadata server)

 

## Section 10: CIS Benshmarks

- Center of Internet security  

- Best practices for the secure configuration of a target system

- download pfd from https://www.cisecurity.org/benchmark/kubernetes

- we can use the command bellow to check ower cluster using aquasec docker run --pid=host -v /etc:/etc:ro -v /var:/var:ro -t docker.io/aquasec/kube-bench:latest [node/master] --version 1.18

- kube-bench run --targets master --check 1.3.2 , once modified run the command watch crictl ps to see if the container is running

 

## Section 11: Verify Platform Binaries

- to download the binary we can head the link: https://github.com/kubernetes/kubernetes

- you can find the binary and the hash on the previous link

- to compare the hash value we use:

    sha512sum binary.tar.gz

    then copy the hash in a file and the official on the second line => to compare use cat file | grep hash  or cat file | uniqu

- Verify api-server binary running insude the container:

    - first we should extract the binary , then you wille find the api-server binary into the kubernetes/server/bin folder

    - the container api-server is very limited , we cant use bash or sh to exec our command, the solution is to list the processes ( ps -aux | grep api-server)

    - find prod/<pid>/root/  | grep api-server

    - sha512sum prod/<pid>/root/usr/local/bin/kube-apiserver >> compare

    - sha512sum kubernetes/server/bin/kube-apiserver >> compare

    - cat compare | uniq

 

## Section 12: Cluster Hardning RBAC

- specify what is allowed, everything else is denied => whitelisting

- Persmissions are additive ( for example a user X have a clusterrole get and delete secret and a role with get secret permissions => So the User  is able to delete and get secrets on all namespace including the one ho has only get secret permission)

- we can test using: auth can-i

- role to clusterroleBinding not possible

- clusterRole to roleBinding possible

- a user in K8s is a cert and a key

 

  ### CertificateSigningRequests sign manually

   openssl genrsa -out 60099.key 2048

   openssl req -new -key 60099.key -out 60099.csr

   openssl x509 -req -in 60099.csr -CA /etc/kubernetes/pki/ca.crt -CAkey /etc/kubernetes/pki/ca.key -CAcreateserial -out 60099.crt -days 500

   k config set-credentials 60099@internal.users --client-key=60099.key --client-certificate=60099.crt

   k config set-context 60099@internal.users --cluster=kubernetes --user=60099@internal.users

   k config get-contexts

   k config use-context 60099@internal.users

   k get ns # fails because no permissions, but shows the correct username returned

 

  ### CertificateSigningRequests sign via API

  openssl genrsa -out 60099.key 2048

  openssl req -new -key 60099.key -out 60099.csr

  cat 60099.csr | base64 | tr -d "\n"  => pour creer certificatesigingrequest

  k -f csr.yaml create

  k get csr # pending

  k certificate approve 60099@internal.users

  k get csr # approved

  k get csr 60099@internal.users -ojsonpath="{.status.certificate}" | base64 -d > 60099.crt

  k config set-credentials 60099@internal.users --client-key=60099.key --client-certificate=60099.crt

  k config set-context 60099@internal.users --cluster=kubernetes --user=60099@internal.users

  k config get-contexts

  k config use-context 60099@internal.users

  k get ns # fails because no permissions, but shows the correct username returned

 

## Section 13: Cluster Hardening using ServiceAccount

- when we add a token to the pod , it have access to all info of the service account

- we can list the files using the command : mount | grep service

- we can check to token on jwt website

- on the pod we can list env to see apiserver adress ...

- we connected to the api using curl -k https://api-server-ip -k -H "Authorisation: Bearer $(cat token)"

  ### disable serviceaccount mounting

  - we can disable mounting serviceaccount when we create the serviceaccount using automountServiceAccountToken: false

  - we can either do it int he pod manifest using automountServiceAccountToken: false

  - to check if a service account is not mounted use command: kubectl exec -it  pod -- mount | grep serviceaccount

 

## Section 14: Cluster HArdening - restrict API access:

- Authentication ( who are you) -> Authorisation ( are you allowed to do ...) -> admission Control ( limit of pods reached, OPA )

   ### anonymous access:

   - we can disable/enable anomynous in the api-server manifest using: --anonymous-auth=false

   ### insecure access

   - insecure access was deleted from the version 1.20

   - but we can still have some cluster with the previous versions

 

## Section 15: Cluster Hardening - Upgrade cluster:

 

## Section 16: MIcroservice Vulnerabilities - Manage Kubernetes Secrets:

 

## Section 20: OPEN POLICY AGENT

- the rego playground https://play.openpolicyagent.org/



## Section 21: Supply chain Security - image Footprint (empreinte)
- layers are created only by ADD COPY RUN on the dockerfile , also the base image can have some layers
- best practice is to use mulit-stage build to reduce image footprint ( from image and another from image on the same dockerfile)
- we should specify the version of used images
- don't run as root
- make filesystem read only ( chmod a-w /etc  : remove writing to the etc directory)
- remove shell access ( rm -rf /bin/* :  to use at the end of the dockerfile , because you can need it to build things before)
- to build and run docker :
    - docker build -t base-image  .
    - docker run --name c1 -d base-imge 
- to see the user who is running the app ,you have to exec into the container , the ps under the vm doesn't show the user how is running the process
- example:
    ``
    FROM ubuntu:20.04
    RUN apt-get update && apt-get -y install curl
    ENV URL https://google.com/this-will-fail?secret-token=
    RUN rm /usr/bin/bash
    CMD ["sh", "-c", "curl --head $URL$TOKEN"]
    ``
    podman build -t app .
    podman run -d -e SECRET=2e064aad-3a90-4cde-ad86-16fad1f8943e app sleep 1d # run in background
    podman ps | grep app
    podman exec -it 4a848daec2e2 bash # fails
    podman exec -it 4a848daec2e2 sh # works

## Section 22: Supply chain Security - Static analysis
- kubesec:
    - is a security risk analysis for kubenetes resources
    - run as Binary, docker container, kubeclt plugin and adminssion controller ( kubesec-webhook)
    - you can copy the ùanifest and it gives you what you should modify (https://kubesec.io)
    - command: docker run -i kubesec/kubesec:512c5e0 scan /dav/stdin < pod.yaml
- OPA Conftest:
    - docker run --rm -v $(pwd):/project instrumanta/conftest test deploy.yaml 

## Section 23: Supply chain Security - Image vulnerabilty scanning
- TRIVY:
    - scanning images vulnerabilies
    - docker run ghcr.io/aquasecurity/trivy:latest image nginx 

## Section 24: Supply chain Security - Secure Supply Chain
- whitelisting Registers with OPA
- ImagePolicyWebhook !!!!!!!!!
        - --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
        - --admission-control-config-file=/etc/kubernetes/policywebhook/admission_config.json

## Section 25: Runtime Securtiy - Behavioral anamytics at host and container level


## Section 28: System hardening - kernel hardening tools

### Apparmor:
- AppArmor is a tool to create another security layer between our applications ans system functionaly
- Applications can have access to filesystem , other preocesses and networks. 
- We can create profiles to allow/disallow things for firefox for example.
- to install appArmor utils use the command: apt install apparmor-utils
- Profile modes:
    - Unconfined: means process can escape ans nothing is enforced
    - Complain:  process can escape but it will be locked if they do so, and we could then investigate the locks ans our logging infrastructure
    - Enforce: process cannot escape  
- Some ApprAromor Commands:
    - show all profiles : aa-status
    - generate a new profile: aa-genprof
    - put orfile in complain mode: aa-complain
    - put profile in enforce mode: aa-enforce
    - update the profile according to the applications needs based on the logs: aa-logprof
    - to apply a new profile: apparmor_parser /etc/apparmor.d/docker-nginx
- AppaArmor profile fo curl:
    aa-genprof curl 
    we can see the created profiles under /etc/apparmor.d
    the  curl profile is named by default: usr.bin.curl 
- Nginx Docker container uses AppAmor profile
    to specify a security options on docker container: docker run --security-opt apparmor=docker-nginx -d  nginx
- Apparmor for Kubernetes Nginx:
    - container runtime needs to support apparmor
    - apparmor nedds to be installed on every node
    - apparmor profilesnedds to be available on every node
    - apparmor profiles are specified per container using annotations
- Create a nginx pod using with an apparmor profile:
    - we use annotations to apply a profile under a pod.

### Seccomp:

- Seccomp stands fot secure  computing mode, it's a security facility in the linux kernel and restricts execution of syscalls made by processes
- Syscalls are exit() sigreturn() read() write() exec() getpid() ...
- Nginx Docker container uses Seccomp profile:
    to specify a security options on docker container: docker run --security-opt seccomp=default.json -d  nginx
- Seccomp for Kubernetes Nginx:
    - we have to make seccomp available for kubelet, create the directory /var/lib/kubelet/seccomp and move the profile file to that directory
    - to enable seccomp we use securityContext section


## Section 29: System hardening - Reduce attack surface
- to list installed services :
    - systemctl list-units --type service 
- to find running services we can use :
    - lsof -i :21 
    - netstat -nlpt | grep 21
- to find a package and delete it:
    - apt show kube-bench
    - apt remove kube-bench
