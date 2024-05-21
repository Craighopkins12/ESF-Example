import EndpointSecurity

class ESFClient {
    var client: OpaquePointer?
    init() {
        // Create Client and event processor
        es_new_client(&client) { _, event in
            // This is where we process the event
            self.processEvent(event: event)
        }
        // Subscribe to Events
        let eventsToSubscribe = [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_AUTH_EXEC]
        es_subscribe(client!, eventsToSubscribe, UInt32(eventsToSubscribe.count))
    }
    
    
    func processEvent(event: UnsafePointer<es_message_t>) {
        // Depending on Event Type send to appropriate function
        switch event.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            parseFileOpen(event: event)
        case ES_EVENT_TYPE_AUTH_EXEC:
            parseExecAuth(event: event)
        default:
            print ("Not Implemented")
        }
    }
    
    func parseFileOpen(event: UnsafePointer<es_message_t>) {
        let filePath = convertString(event.pointee.event.open.file.pointee.path)
        let processPath = convertString(event.pointee.process.pointee.executable.pointee.path)
        print ("Filepath \(filePath)")
    }
    
    func convertString(_ token: es_string_token_t) -> String {
        guard token.length > 0 else {
            return ""
        }
        return String(cString: token.data)
    }
    
    
    func parseExecAuth(event: UnsafePointer<es_message_t>) {
        var decision = ES_AUTH_RESULT_ALLOW
        let signingID = convertString(event.pointee.event.exec.target.pointee.signing_id)
        // Decide if action should be blocked
        if signingID == "com.unwantedApp.test" {
            decision = ES_AUTH_RESULT_DENY
        }
        // Get Arguments for launching the process
        let arguments = getProcessArguments(exec: event.pointee.event.exec)
        // Check the Arguments for blocking
        if (signingID == "com.apple.xpc.launchctl" && arguments.contains("bootout")) {
            decision = ES_AUTH_RESULT_DENY
        }
        // Apply the decision to the event
        es_respond_auth_result(client!, event, decision, false)
    }
    
    func getProcessArguments(exec: es_event_exec_t) -> [String] {
        var ref: es_event_exec_t = exec
        let argCount = es_exec_arg_count(&ref)
        var arguments: [String] = []
        for key in 0 ..< argCount {
            let argument = convertString(es_exec_arg(&ref, key))
            arguments.append(argument)
        }
        return arguments
    }
    
}
