# azure-go-sdk
An SDK for interacting with Azure resources in Go

## Status

This library is a work in progress.  

## Using the Go SDK

To use a service in the SDK, create a service variable by calling the `New()`
function. Once you have a service client, you can call API operations which each
return response data and a possible error.

To send a message to a Service Bus Topic, then retrieve and delete it from a Subscription:

```go
package main

import (
	"fmt"

	"github.com/botlink/azure-go-sdk/servicebusclassic"
)

func main() {
	sender := servicebusclassic.New("namespace", "SASPolicyName", "SASKey")
	senderTopic := sender.GetTopic("topic-name")
	err := senderTopic.Send("Hello World!")
	if err != nil {
		panic(err)
	}

	listener := servicebusclassic.New("namespace", "SASPolicyName", "SASKey")
	listenerTopic := listener.GetTopic("topic-name")
	listenerTopic.SetSubscription("subscription-name")
	message, err := listenerTopic.PeekLockMessage(30)
	if err != nil {
		panic(err)
	}

	if message != nil {
		fmt.Printf("The message body is: %s\n", message.Body)
		err = listenerTopic.DeleteMessage(message)
		if err != nil {
			panic(err)
		}
	}
}
```
