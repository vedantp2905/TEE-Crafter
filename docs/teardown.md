# Teardown: what `destroy` removes, and the three things that outlive it

`tee-crafter destroy` runs `terraform destroy` against the deploy's own state, so
everything Terraform created goes away: the instance, its disk, the VPC/VNet, the
NAT gateway, the Bastion host, the flow-log workspace, the storage account.

Three categories of resource survive on purpose or by provider design. None of
them is a leak, and all three will make a resource count in an old project look
alarming if you do not know about them.

## GCP Cloud KMS keyrings and keys cannot be deleted — ever

There is no delete API for either
([Cloud KMS object hierarchy](https://cloud.google.com/kms/docs/resource-hierarchy)),
only for individual key *versions*. Each GCP deploy creates a keyring plus a key
for its disk encryption, so the namespace grows by one of each per deploy and
never shrinks. A test project with no instances, disks, networks or buckets left
in it can still hold hundreds of keyrings.

The cost half is handled: billing is per active key version, and destroying the
version stops it. Per-deploy keys deliberately carry **no** `rotation_period` — a
90-day schedule on an ephemeral key can only fire *after* the deploy is
abandoned, which would quietly mint a fresh billable version every quarter,
forever.

To reclaim a key version by hand:

```bash
gcloud kms keys versions destroy 1 --key=<key> --keyring=<ring> --location=us-central1
```

## AWS EBS snapshots survive `deregister-image`

Retiring a baked AMI leaves its 30 GiB snapshot billing at roughly $1.50/month,
and the snapshot id is only discoverable while the AMI still exists. Every AWS
bake therefore records it in
`apps/cli/src/tee_crafter/measurements/aws_ebs_snapshots.json`. See
[aws_setup.md](aws_setup.md#retiring-an-ami-leaves-its-ebs-snapshot-behind).

## Azure leaves Network Watcher artifacts behind

VNet flow logs cause the platform to create a data-collection endpoint and rule
(`NWTA-*`) that Terraform did not create and so does not destroy. They cost
nothing, but they keep the resource group alive. Delete the group itself:

```bash
az group delete --name tee-crafter-<platform>-rg-<suffix> --yes
```

Azure accepts that call asynchronously and can abandon it: the group's
`provisioningState` goes to `Deleting` and then reverts to `Succeeded` with
everything still present, usually because a resource in the group was still
mid-create. `tee-crafter destroy` re-issues the delete when it sees that happen.
If you are deleting by hand, confirm the group is actually gone rather than
trusting the command's exit status:

```bash
az group show --name tee-crafter-<platform>-rg-<suffix> --query properties.provisioningState -o tsv
```

## Baked images are never destroyed by a deploy teardown

Images are the expensive, reusable artifact — one bake serves many deploys — so
no deploy removes one. Retiring them is a separate, deliberate act:

| Cloud | Baked artifact | Retire with |
|---|---|---|
| AWS | AMI + its EBS snapshot | `aws ec2 deregister-image`, then delete the recorded snapshot |
| Azure | Shared Image Gallery version in `tee-crafter-images-<platform>-rg` | `az sig image-version delete` |
| GCP | Compute image | `gcloud compute images delete` |

## Interrupted applies

**Killing the CLI does not cancel anything the cloud has already been asked to
do.** This is the expensive version of the problem and it is easy to get wrong.
A `gpu-cc-azure` apply killed within a minute of starting,
because the run was misconfigured; Azure went on to finish provisioning the
H100 and *started* it roughly half an hour later. The resource-group delete
issued during that window was abandoned in the way described above — state went
`Deleting`, then back to `Succeeded` with the new VM present — and the instance
billed until a routine sweep caught it.

So after interrupting an apply, do not assume the spend stopped. Destroy
explicitly, then verify that compute is actually gone rather than trusting an
exit code:

```bash
az vm list -d --query "[].{n:name,s:powerState}" -o tsv
az network bastion list --query "length(@)" -o tsv # bastions bill without a VM
```

A `terraform apply` killed mid-create can also leave a resource live in the cloud
and absent from state. A resumed `deploy-from-build` adopts such a resource
automatically — it imports it before re-applying — but only when it can prove
ownership: the resource must sit in this deploy's own resource group, or carry
this deploy's unique suffix. Anything else it refuses to touch and reports, so a
resource belonging to another deploy is never written into your state.
