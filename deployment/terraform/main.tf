terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.8"
    }
  }
}

provider "kubernetes" {
  config_path = "~/.kube/config"
}

provider "helm" {
  kubernetes {
    config_path = "~/.kube/config"
  }
}

resource "helm_release" "jade_ultimate" {
  name       = "jade-ultimate"
  chart      = "${path.module}/../kubernetes/helm"
  namespace  = "jade-security"
  create_namespace = true
  values     = [file("${path.module}/../kubernetes/helm/values.yaml")]
}