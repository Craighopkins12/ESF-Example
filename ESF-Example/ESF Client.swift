import EndpointSecurity

class ESFClient {
    var client: OpaquePointer?
    init() {
        // Create Client and event processor
        es_new_client(&client) { _, event in
                // This is where we process the event
            processEvent(event: event)
        }
        // Subscribe to Events
        let eventsToSubscribe = [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_AUTH_EXEC]
        es_subscribe(client!, eventsToSubscribe, UInt32(eventsToSubscribe.count))
    }
}

func processEvent(event: UnsafePointer<es_message_t>) {
    // Add Code to Process the Event
}
