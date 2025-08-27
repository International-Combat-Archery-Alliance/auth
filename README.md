# ICAA Auth Library

A Go authentication library for the International Combat Archery Alliance (ICAA) that provides Google OAuth ID token validation with role-based access control.

## Features

- Google OAuth ID token validation
- Role-based authentication (admin vs regular users)
- Token expiration handling
- User profile information extraction
- Clean interface design for easy integration

## Installation

```bash
go get github.com/International-Combat-Archery-Alliance/auth
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    
    "github.com/International-Combat-Archery-Alliance/auth"
    "github.com/International-Combat-Archery-Alliance/auth/google"
)

func main() {
    ctx := context.Background()
    
    // Create a Google token validator
    validator, err := google.NewValidator(ctx)
    if err != nil {
        panic(err)
    }
    
    // Validate a token
    token := "your-google-id-token"
    audience := "your-google-client-id"
    
    authToken, err := validator.Validate(ctx, token, audience)
    if err != nil {
        fmt.Printf("Token validation failed: %v\n", err)
        return
    }
    
    // Access user information
    fmt.Printf("User email: %s\n", authToken.UserEmail())
    fmt.Printf("Profile picture: %s\n", authToken.ProfilePicURL())
    fmt.Printf("Is admin: %t\n", authToken.IsAdmin())
    fmt.Printf("Expires at: %v\n", authToken.ExpiresAt())
}
```

## Core Interfaces

### AuthToken

The `AuthToken` interface provides access to validated token information:

```go
type AuthToken interface {
    ExpiresAt() time.Time     // Token expiration time
    ProfilePicURL() string    // User's profile picture URL
    IsAdmin() bool           // Whether user has admin privileges
    UserEmail() string       // User's email address
}
```

### Validator

The `Validator` interface handles token validation:

```go
type Validator interface {
    Validate(ctx context.Context, token string, audience string) (AuthToken, error)
}
```

## Admin Access Control

Admin privileges are granted to users with Google Workspace accounts from the `icaa.world` domain. Regular users from other domains will have `IsAdmin()` return `false`.

## Google Provider

The Google provider validates Google ID tokens and extracts user information from the JWT claims.

### Creating a Validator

```go
import "github.com/International-Combat-Archery-Alliance/auth/google"

validator, err := google.NewValidator(ctx)
if err != nil {
    // Handle error
}
```

### Token Claims

The Google provider extracts the following claims from ID tokens:

- `email` - User's email address
- `picture` - Profile picture URL
- `hd` - Hosted domain (used for admin detection)
- `exp` - Token expiration timestamp

## Requirements

- Go 1.24.6 or later
- Valid Google OAuth 2.0 client credentials
- Network access to Google's token validation endpoints

## Dependencies

This library uses Google's official Go client library for ID token validation:

- `google.golang.org/api/idtoken` - Google ID token validation

## License

This project is licensed under the GNU Affero General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## Contributing

This library is developed for the International Combat Archery Alliance. Please ensure any contributions align with the organization's authentication requirements.