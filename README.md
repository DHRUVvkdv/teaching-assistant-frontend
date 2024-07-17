# AI-Enhanced Teaching Assistant: Bridging Instructor Knowledge and Web Intelligence

## Project Live Link

[Click here to view the live project](https://teachingassistant-dv.streamlit.app/)
[![Instructor side]](https://youtu.be/aX303VJL-Ew)
[![Student side]](https://youtu.be/aDXYTqY8-R4)

## Table of Contents

- [Description](#description)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Setup and Installation](#setup-and-installation)
- [Usage](#usage)
- [User Authentication](#user-authentication)
- [Instructor Portal](#instructor-portal)
- [Customization Options](#customization-options)
- [API Integration](#api-integration)
- [AWS Services Used](#aws-services-used)
- [Contributing](#contributing)
- [License](#license)

## Description

The Educational Query Assistant is a Streamlit-based web application that allows users to query educational content from various professors and receive responses based on the professor's notes and internet sources. It features user authentication, an instructor portal, and customizable UI options.

## Features

- User authentication (sign up, sign in, email verification)
- Instructor mode for managing documents
- Multi-language support for query responses
- Customizable UI themes and fonts
- Integration with AWS services (Cognito, S3, DynamoDB)
- API integration for processing queries and documents

## Technologies Used

- Python
- Streamlit
- AWS (Cognito, S3, DynamoDB)
- Boto3
- Requests
- Pandas

## Setup and Installation

1. Clone the repository:
   '''sh
   git clone https://github.com/DHRUVvkdv/teaching-assistant-frontend.git

2. Install the required package
   ```sh
   pip install -r requirements.txt
   ```
3. Set up your AWS credentials and configure the necessary services (Cognito, S3, DynamoDB).
4. Create a `secrets.toml` file in the `.streamlit` directory with the following content:

```toml
API_BASE_URL = "your_api_base_url"
API_KEY = "your_api_key"
USER_POOL_ID = "your_cognito_user_pool_id"
CLIENT_ID = "your_cognito_client_id"
AWS_DEFAULT_REGION = "your_aws_region"
S3_BUCKET_NAME = "your_s3_bucket_name"
DYNAMODB_TABLE_NAME = "your_dynamodb_table_name"
```

5. Run the Streamlit app:
   ```sh
   streamlit run app.py
   ```

## Usage

1. Sign up or sign in to access the main application.
2. Select a professor and enter your query in the text area.
3. Choose your preferred output language.
4. Submit the query and view the results, including professor's notes and internet sources.

## User Authentication

- Users can sign up with email and password.
- Email verification is required after sign-up.
- Users can sign in with their credentials.
- Instructor status can be toggled in the user settings.

## Instructor Portal

- Accessible to users with instructor privileges.
- Upload PDF documents for specific professors.
- View and manage uploaded documents.
- Trigger processing of uploaded documents.

## Customization Options

- Multiple UI themes available (e.g., Accessible Light, Accessible Dark, Pastel).
- Font selection for better readability.
- Language selection for query responses.

## API Integration

The application integrates with a backend API for:

- Processing user queries
- Handling document uploads and processing
- Retrieving professor-specific information

## AWS Services Used

- Cognito: User authentication and management
- S3: Document storage
- DynamoDB: Storing processed document information

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.
