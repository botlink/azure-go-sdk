package servicebusclassic

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Based on https://msdn.microsoft.com/en-us/library/azure/hh780762.aspx

// The ServiceBus type encapsulates operation with a ServiceBus namespace.
type ServiceBus struct {
	namespace string
	saKey     string
	saValue   string
	client    *http.Client
}

func New(namespace string, SASKeyName string, SASKeyValue string) *ServiceBus {
	return &ServiceBus{
		namespace: namespace,
		saKey:     SASKeyName,
		saValue:   SASKeyValue,
		client:    &http.Client{},
	}
}

// Topic Reference to a Topic
type Topic struct {
	*ServiceBus
	TopicPath    string
	Subscription string
}

type BrokeredMessage struct {
	// TODO: Fill in remaining fields from https://msdn.microsoft.com/en-us/library/azure/microsoft.servicebus.messaging.brokeredmessage.aspx
	DeliveryCount          int
	EnqueuedSequenceNumber int
	LockToken              string
	MessageId              string
	SequenceNumber         int
	State                  string
	TimeToLive             int
}

type Message struct {
	BrokerProperties BrokeredMessage
	Location         string
	Body             string
}

func (s *ServiceBus) GetTopic(path string) (t *Topic) {
	return &Topic{s, path, ""}
}

func (t *Topic) SetSubscription(subscription string) {
	t.Subscription = subscription
}

// Send Message
func (t *Topic) Send(messageBody string) error {
	url := fmt.Sprintf("https://%s.servicebus.windows.net/%s/messages", t.ServiceBus.namespace, t.TopicPath)
	_, err := t.ServiceBus.requestWithBody(url, "POST", messageBody)
	return err
}

// Send Message Batch
// TODO: Implement

// Receive and Delete Message (Destructive Read)
// TODO: Implement

// Peek-Lock Message (Non-Destructive Read)
func (t *Topic) PeekLockMessage(timeout int) (*Message, error) {
	url := fmt.Sprintf("https://%s.servicebus.windows.net/%s/subscriptions/%s/messages/head?timeout=%d",
		t.ServiceBus.namespace, t.TopicPath, t.Subscription, timeout)
	resp, err := t.ServiceBus.request(url, "POST")
	defer resp.Body.Close()

	if resp.StatusCode == 204 {
		return nil, nil
	}

	var message Message
	brokerProperties := resp.Header.Get("BrokerProperties")
	location := resp.Header.Get("Location")

	if err := json.Unmarshal([]byte(brokerProperties), &message.BrokerProperties); err != nil {
		return nil, fmt.Errorf("Error unmarshalling BrokerProperties: %v", err)
	}

	mBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading message body")
	}

	message.Location = location
	message.Body = string(mBody)

	return &message, nil
}

// Unlock Message
// TODO: Implement

// Delete Message
func (t *Topic) DeleteMessage(message *Message) error {
	url := fmt.Sprintf("https://%s.servicebus.windows.net/%s/subscriptions/%s/messages/%d/%s",
		t.ServiceBus.namespace, t.TopicPath, t.Subscription, message.BrokerProperties.SequenceNumber, message.BrokerProperties.LockToken)
	_, err := t.ServiceBus.request(url, "DELETE")
	return err
}

// Renew-Lock for a Message
// TODO: Implement

// Request a Token from ACS
// TODO: Implement

func (s *ServiceBus) requestWithBody(url string, method string, body string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", s.authHeader(url, s.signatureExpiry(time.Now())))

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}

	if (resp.StatusCode == http.StatusCreated) || (resp.StatusCode == http.StatusOK) {
		return resp, nil
	}

	return nil, fmt.Errorf("Error code: %v\n", resp.StatusCode)
}

func (s *ServiceBus) request(url string, method string) (*http.Response, error) {
	data, err := s.requestWithBody(url, method, "")
	return data, err
}

//authHeader returns the value of the Authorization header for requests to Azure Service Bus.
//
//It's translated from the Python client:
//https://github.com/Azure/azure-sdk-for-python/blob/master/azure-servicebus/azure/servicebus/servicebusservice.py
func (s *ServiceBus) authHeader(uri string, expiry string) string {
	u := s.signatureURI(uri)
	sts := s.stringToSign(u, expiry)
	sig := s.signString(sts)
	return fmt.Sprintf("SharedAccessSignature sig=%s&se=%s&skn=%s&sr=%s", sig, expiry, s.saKey, u)
}

//signatureExpiry returns the expiry for the shared access signature for the next request.
//
//It's translated from the Python client:
// https://github.com/Azure/azure-sdk-for-python/blob/master/azure-servicebus/azure/servicebus/servicebusservice.py
func (s *ServiceBus) signatureExpiry(from time.Time) string {
	t := from.Add(300 * time.Second).Round(time.Second).Unix()
	return strconv.Itoa(int(t))
}

//signatureURI returns the canonical URI according to Azure specs.
//
//It's translated from the Python client:
//https://github.com/Azure/azure-sdk-for-python/blob/master/azure-servicebus/azure/servicebus/servicebusservice.py
func (s *ServiceBus) signatureURI(uri string) string {
	return strings.ToLower(url.QueryEscape(uri))
}

//stringToSign returns the string to sign.
//
//It's translated from the Python client:
//https://github.com/Azure/azure-sdk-for-python/blob/master/azure-servicebus/azure/servicebus/servicebusservice.py
func (s *ServiceBus) stringToSign(uri string, expiry string) string {
	return uri + "\n" + expiry
}

//signString returns the HMAC signed string.
//
//It's translated from the Python client:
//https://github.com/Azure/azure-sdk-for-python/blob/master/azure-servicebus/azure/servicebus/_common_conversion.py
func (s *ServiceBus) signString(sts string) string {
	h := hmac.New(sha256.New, []byte(s.saValue))
	h.Write([]byte(sts))
	encodedSig := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return url.QueryEscape(encodedSig)
}
