$body = @{
  model = "gpt-4o-mini"
  messages = @(
    @{
      role = "user"
      content = "Please summarize this. My email is test@example.com and api_key=abcdef1234567890."
    }
  )
} | ConvertTo-Json -Depth 10

Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:8080/v1/chat/completions" `
  -ContentType "application/json" `
  -Body $body

