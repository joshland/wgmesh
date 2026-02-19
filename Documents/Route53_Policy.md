## Route53 Policy Example

This is an example policy which will function to allow the wgsite node to publish all required records.


    {
        "Statement": [
            {
                "Action": [
                    "route53:GetChange",
                    "route53:ListHostedZones"
                ],
                "Effect": "Allow",
                "Resource": "*",
                "Sid": "GlobalPolicyRules"
            },
            {
                "Action": [
                    "route53:GetHostedZone",
                    "route53:ListHostedZonesByName",
                    "route53:ListResourceRecordSets"
                ],
                "Effect": "Allow",
                "Resource": "arn:aws:route53:::hostedzone/ZXXXXXXXXXXX"
            },
            {
                "Action": "route53:ChangeResourceRecordSets",
                "Condition": {
                    "ForAllValues:StringLike": {
                        "route53:ChangeResourceRecordSetsNormalizedRecordNames": [
                            "corp.example.com",
                            "*.corp.example.com",
                            "*.feb17.corp.example.com",
                            "*.*.corp.example.com"
                        ],
                        "route53:ChangeResourceRecordSetsRecordTypes": [
                            "TXT",
                            "A",
                            "AAAA"
                        ]
                    }
                },
                "Effect": "Allow",
                "Resource": "arn:aws:route53:::hostedzone/ZXXXXXXXXXXX"
            }
        ],
        "Version": "2012-10-17"
    }
