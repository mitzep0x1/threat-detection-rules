rule Hello_World {
  meta:
    author = "lr2t9iz"
    description = "Hello World"

  strings:
    $domain1 = "example.com"
  
  condition:
    any of them
}