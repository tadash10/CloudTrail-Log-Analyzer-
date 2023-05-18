import boto3

def retrieve_latest_delivery_time(trail_name):
    """
    Retrieves the latest delivery time of CloudTrail logs for a specific trail.
    """
    cloudtrail = boto3.client('cloudtrail')
    response = cloudtrail.get_trail_status(Name=trail_name)
    return response['LatestDeliveryTime']

def retrieve_events(trail_name, event_names, start_time):
    """
    Retrieves CloudTrail events for a specific trail, event names, and start time.
    """
    cloudtrail = boto3.client('cloudtrail')
    response = cloudtrail.lookup_events(
        LookupAttributes=[
            {'AttributeKey': 'EventName', 'AttributeValue': event_name}
            for event_name in event_names
        ],
        StartTime=start_time
    )
    return response.get('Events', [])

def analyze_event(event):
    """
    Analyzes a CloudTrail event and returns a report of potential security issues.
    """
    event_name = event['EventName']
    event_time = event['EventTime']
    event_source = event['EventSource']
    report = []

    # Analyze event for potential security issues
    if event_name == 'CreateSecurityGroup':
        report.append("Potential unauthorized security group creation.")
    elif event_name == 'AuthorizeSecurityGroupIngress':
        report.append("Potential unauthorized security group ingress rule modification.")
    elif event_name == 'AuthorizeSecurityGroupEgress':
        report.append("Potential unauthorized security group egress rule modification.")
    
    # Add more analysis logic for other events as needed
    
    return {
        'EventName': event_name,
        'EventTime': event_time,
        'EventSource': event_source,
        'Report': report
    }

def analyze_cloudtrail_logs():
    cloudtrail = boto3.client('cloudtrail')
    
    # Retrieve the names of all available CloudTrail trails
    response = cloudtrail.describe_trails()
    trail_names = [trail['Name'] for trail in response['trailList']]
    
    for trail_name in trail_names:
        latest_delivery_time = retrieve_latest_delivery_time(trail_name)
        
        event_names = ['CreateSecurityGroup', 'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress']
        events = retrieve_events(trail_name, event_names, latest_delivery_time)
        
        if events:
            print(f"Potential security issues found in CloudTrail log for trail: {trail_name}")
            for event in events:
                analysis_result = analyze_event(event)
                print(f"- Event Name: {analysis_result['EventName']}")
                print(f"  Event Time: {analysis_result['EventTime']}")
                print(f"  Event Source: {analysis_result['EventSource']}")
                for issue in analysis_result['Report']:
                    print(f"  Issue: {issue}")

if __name__ == '__main__':
    analyze_cloudtrail_logs()
