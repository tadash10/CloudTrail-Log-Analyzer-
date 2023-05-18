import boto3

def analyze_cloudtrail_logs():
    cloudtrail = boto3.client('cloudtrail')
    
    # Retrieve the latest CloudTrail log files
    response = cloudtrail.describe_trails()
    trail_names = [trail['Name'] for trail in response['trailList']]
    
    for trail_name in trail_names:
        response = cloudtrail.get_trail_status(Name=trail_name)
        latest_delivery_time = response['LatestDeliveryTime']
        
        response = cloudtrail.lookup_events(
            LookupAttributes=[
                {'AttributeKey': 'EventName', 'AttributeValue': 'CreateSecurityGroup'},
                {'AttributeKey': 'EventName', 'AttributeValue': 'AuthorizeSecurityGroupIngress'},
                {'AttributeKey': 'EventName', 'AttributeValue': 'AuthorizeSecurityGroupEgress'}
            ],
            StartTime=latest_delivery_time
        )
        
        if 'Events' in response:
            print(f"Potential security issues found in CloudTrail log for trail: {trail_name}")
            for event in response['Events']:
                event_name = event['EventName']
                event_time = event['EventTime']
                event_source = event['EventSource']
                print(f"- Event Name: {event_name}")
                print(f"  Event Time: {event_time}")
                print(f"  Event Source: {event_source}")
                # Additional actions to analyze and report potential security issues

if __name__ == '__main__':
    analyze_cloudtrail_logs()
