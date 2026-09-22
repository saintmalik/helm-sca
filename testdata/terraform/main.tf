resource "helm_release" "demo" {
  name  = "demo-tf"
  chart = "../charts/demo"

  set {
    name  = "image.tag"
    value = "ignored"
  }
}

resource "kubernetes_deployment_v1" "web" {
  metadata {
    name = "web"
  }
  spec {
    template {
      spec {
        container {
          name  = "app"
          image = "nginx:1.27.0"
        }
      }
    }
  }
}
