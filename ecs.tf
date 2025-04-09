# ECS Cluster
module "ecs" {
  source  = "terraform-aws-modules/ecs/aws"
  version = "5.11.4"

  cluster_name = "my-ecs-cluster"

  tags = {
    Project = var.project_name
  }
}

resource "aws_ecs_task_definition" "nginx_task" {
  family = "nginx-task"
  container_definitions = jsonencode([
    {
      name      = "nginx-container"
      image     = "595140864345.dkr.ecr.us-east-1.amazonaws.com/nginx-200-ok:latest"
      memory    = 512
      cpu       = 256
      essential = true
      portMappings = [
        {
          containerPort = 3000
          hostPort      = 3000
          protocol      = "tcp"
        }
      ]
      command = [
        "nginx", "-g", "daemon off;"
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_log_group.name
          "awslogs-region"        = "us-east-1"
          "awslogs-stream-prefix" = "nginx"
        }
      }
    }
  ])
  requires_compatibilities = ["EC2"]
  network_mode             = "bridge"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
}

resource "aws_ecs_service" "nginx_service" {
  name            = "nginx-service"
  cluster         = module.ecs.cluster_id
  task_definition = aws_ecs_task_definition.nginx_task.arn
  desired_count   = 1
  launch_type     = "EC2"

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  depends_on = [aws_autoscaling_group.ecs]
}

resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecs-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "ecs_task_execution_policy" {
  name       = "ecs-task-execution-policy"
  roles      = [aws_iam_role.ecs_task_execution_role.name]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_instance_profile" "ecs_instance_profile" {
  name = "ecs-instance-profile"

  role = aws_iam_role.ecs_instance_role.name
}

resource "aws_iam_role" "ecs_instance_role" {
  name = "ecs-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "ecs_instance_policy" {
  name        = "ECSInstancePolicy"
  description = "Policy for EC2 instances in ECS cluster"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ecs:CreateCluster",
          "ecs:DeregisterContainerInstance",
          "ecs:DiscoverPollEndpoint",
          "ecs:Poll",
          "ecs:RegisterContainerInstance",
          "ecs:StartTelemetrySession",
          "ecs:UpdateContainerInstancesState",
          "ecs:Submit*",
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "ecs_instance_policy" {
  name       = "ecs-instance-policy"
  roles      = [aws_iam_role.ecs_instance_role.name]
  policy_arn = aws_iam_policy.ecs_instance_policy.arn
}


# resource "aws_iam_policy_attachment" "ecs_instance_policy" {
#   name       = "ecs-instance-policy"
#   roles      = [aws_iam_role.ecs_instance_role.name]
#   policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerServiceforEC2Role"
# }

# // Deptrecated 
# resource "aws_launch_configuration" "ecs" {
#   name          = "ecs-launch-configuration"
#   image_id      = data.aws_ami.ecs.id
#   instance_type = "t3.micro"
#   key_name      = "ghost-ec2-pool"

#   iam_instance_profile = aws_iam_instance_profile.ecs_instance_profile.name
#   security_groups      = [aws_security_group.ecs.id]


#   root_block_device {
#     volume_size = 30
#     volume_type = "gp2"
#   }

#   lifecycle {
#     create_before_destroy = true
#   }
# }
resource "aws_launch_template" "ecs" {
  name          = "ecs-launch-template"
  image_id      = data.aws_ami.ecs.id
  instance_type = "t4g.micro"
  key_name      = "ghost-ec2-pool"

  iam_instance_profile {
    name = aws_iam_instance_profile.ecs_instance_profile.name
  }

  network_interfaces {
    security_groups = [aws_security_group.ecs.id]
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 30
      volume_type = "gp2"
    }
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    echo ECS_CLUSTER=${module.ecs.cluster_name} >> /etc/ecs/ecs.config
  EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags = {
      Project = var.project_name
    }
  }
}


resource "aws_security_group" "ecs" {
  name        = "ecs-security-group"
  description = "Allow traffic to ECS instances"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Доступ по SSH
  }

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Доступ к контейнеру
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Project = var.project_name
  }
}

resource "aws_autoscaling_group" "ecs" {
  name = "ecs-autoscaling-group"
  launch_template {
    id      = aws_launch_template.ecs.id
    version = "$Latest"
  }
  min_size            = 1
  max_size            = 3
  desired_capacity    = 1
  vpc_zone_identifier = module.vpc.private_subnets

  tag {
    key                 = "Project"
    value               = var.project_name
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_policy" "scale_up" {
  name                   = "scale-up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.ecs.name
}

resource "aws_autoscaling_policy" "scale_down" {
  name                   = "scale-down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.ecs.name
}

resource "aws_cloudwatch_log_group" "ecs_log_group" {
  name = "/ecs/nginx-container"
}

data "aws_ami" "ecs" {
  owners      = ["amazon"]
  most_recent = true

  filter {
    name   = "name"
    values = ["amzn2-ami-ecs-hvm-*-arm64-*"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }
}