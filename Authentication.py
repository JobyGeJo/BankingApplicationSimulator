from datetime import datetime, timedelta
import jwt
from jwt import DecodeError, InvalidSignatureError
import extra_streamlit_components as stx

from typing import Optional
import streamlit as st

import time

from utilities.validator import Validator
from streamlit_authenticator.utilities.hasher import Hasher
from streamlit_authenticator.utilities.helpers import Helpers
from streamlit_authenticator.utilities.exceptions import (CredentialsError,
                                                            ForgotError,
                                                            LoginError,
                                                            RegisterError,
                                                            ResetError,
                                                            UpdateError)

from random import randint


class CookieHandler:

    def __init__(self, cookie_name: str, cookie_key: str, cookie_expiry_days: float=30.0):

        self.cookie_name            =   cookie_name
        self.cookie_key             =   cookie_key
        self.cookie_expiry_days     =   cookie_expiry_days
        self.cookie_manager         =   stx.CookieManager()
        self.token                  =   None
        self.exp_date               =   None

    def get_cookie(self) -> str:

        if st.session_state['logout']:
            return False
        self.token = self.cookie_manager.get(self.cookie_name)
        if self.token is not None:
            self.token = self._token_decode()
            if (self.token is not False and 'username' in self.token and
                self.token['exp_date'] > datetime.utcnow().timestamp()):
                return self.token
            
    def delete_cookie(self):

        try:
            self.cookie_manager.delete(self.cookie_name)
        except KeyError as e:
            print(e)
    def set_cookie(self):

        self.exp_date = self._set_exp_date()
        token = self._token_encode()
        self.cookie_manager.set(self.cookie_name, token,
                                expires_at=datetime.now() + timedelta(days=self.cookie_expiry_days))
        
    def _set_exp_date(self) -> str:
        return (datetime.utcnow() + timedelta(days=self.cookie_expiry_days)).timestamp()
    
    def _token_decode(self) -> str:

        try:
            return jwt.decode(self.token, self.cookie_key, algorithms=['HS256'])
        except InvalidSignatureError as e:
            print(e)
            return False
        except DecodeError as e:
            print(e)
            return False
    def _token_encode(self) -> str:

        return jwt.encode({'username': st.session_state['username'],
            'exp_date': self.exp_date}, self.cookie_key, algorithm='HS256')

class AuthenticationHandler:

    def __init__(self, credentials: dict, cookie_name: str, cookie_key: str,
                 cookie_expiry_days: float=30.0, validator: Optional[Validator]=None):

        self.credentials                =   credentials
        self.validator                  =   validator if validator is not None else Validator()
        self.random_password            =   None

        for username, _ in self.credentials['user_accounts'].items():
            if 'logged_in' not in self.credentials['user_accounts'][username]:
                self.credentials['user_accounts'][username]['logged_in'] = False
            if 'failed_login_attempts' not in self.credentials['user_accounts'][username]:
                self.credentials['user_accounts'][username]['failed_login_attempts'] = 0
            if not Hasher._is_hash(self.credentials['user_accounts'][username]['password']):
                self.credentials['user_accounts'][username]['password'] = \
                    Hasher._hash(self.credentials['user_accounts'][username]['password'])
        if 'name' not in st.session_state:
            st.session_state['name'] = None
        if 'authentication_status' not in st.session_state:
            st.session_state['authentication_status'] = None
        if 'username' not in st.session_state:
            st.session_state['username'] = None
        if 'logout' not in st.session_state:
            st.session_state['logout'] = None

    def check_credentials(self, username: str, password: str) -> bool:
            
        if username in self.credentials['user_accounts']:

            print(self.credentials['user_accounts'][username])
            
            if self.credentials['user_accounts'][username]['failed_login_attempts'] >= 5:
                    raise LoginError('Maximum number of login attempts exceeded')
            try:
                if Hasher.check_pw(password, self.credentials['user_accounts'][username]['password']):
                    return True
                st.session_state['authentication_status'] = False
                self._record_failed_login_attempts(username)
                return False
            except TypeError as e:
                print(e)
            except ValueError as e:
                print(e)
        else:
            st.session_state['authentication_status'] = False
            return False
        return None

    def _credentials_contains_value(self, value: str) -> bool:
        return any(value in d.values() for d in self.credentials['user_details'].values())
    
    def generate_account_no(self) -> int:
        account_no = randint(10000, 99999)
        while account_no in set(self.credentials['user_accounts'].keys()):
            account_no = randint(10000, 99999)

        return account_no

    def _register_credentials(self, username: str, password: str, email: str, mobile: str, 
                              account_type: str, address: str, date_of_birth: datetime, id_proof: str):

        if not self.validator.validate_email(email):
            raise RegisterError('Email is not valid')
        if self._credentials_contains_value(email):
            raise RegisterError('Email already taken')

        if not self.validator.validate_name(username):
            raise RegisterError('Username is not valid')

        if not self.validator.validate_phone_no(mobile):
            raise RegisterError('Mobile number is not valid')
        if self._credentials_contains_value(mobile):
            raise RegisterError('Mobile number already taken')
        
        account_no = self.generate_account_no()

        self.credentials['user_accounts'][account_no] = {

            'name': username, 
            'password': Hasher([password]).generate()[0], 
            'logged_in': False, 

        }
        
        self.credentials['user_details'][account_no] = {

            'name': username,
            'address': address,
            'mobile': int(mobile),
            'email': email,
            'account_type': account_type,
            'date_of_birth': date_of_birth,
            'id': id_proof,
            'transactions': {f"{datetime.now():%b %d %Y %H:%M:%S}": {
                'action': 'deposit',
                'before amount': 0,
                'after amount': 1000
            }}

        }

        if account_type != "Admin":
            self.credentials['user_details'][account_no].setdefault('balance', 1000)

        return account_no

    def register_user(self, password: str, password_repeat: str, username: str, email: str, mobile_no: str, 
                      account_type: str, address: str, date_of_birth, id_proof: str):

        if not self.validator.validate_length(password, 1) \
            or not self.validator.validate_length(password_repeat, 1):
            raise RegisterError('Password/repeat password fields cannot be empty')

        if password != password_repeat:
            raise RegisterError('Passwords do not match')

        else:
            return self._register_credentials(username, password, email, mobile_no, account_type, address, date_of_birth, id_proof)

    def execute_logout(self):

        self.credentials['user_accounts'][st.session_state['username']]['logged_in'] = False
        st.session_state['logout'] = True
        st.session_state['name'] = None
        st.session_state['username'] = None
        st.session_state['authentication_status'] = None

    def _set_random_password(self, username: str) -> str:
        self.random_password = Helpers.generate_random_pw()
        self.credentials['user_accounts'][username]['password'] = \
            Hasher([self.random_password]).generate()[0]
        return self.random_password

    def _update_password(self, username: str, password: str):
        self.credentials['user_accounts'][username]['password'] = Hasher([password]).generate()[0]

    def reset_password(self, username: str, password: str, new_password: str,
                       new_password_repeat: str) -> bool:

        if self.check_credentials(username, password):
            if not self.validator.validate_length(password, 1):
                raise ResetError('No new password provided')
            if new_password != new_password_repeat:
                raise ResetError('Passwords do not match')
            if new_password != password:
                self._update_password(username, password)
                return True
            else:
                raise ResetError('New and current passwords are the same')
        else:
            raise CredentialsError('password')

    def _record_failed_login_attempts(self, username: str, reset: bool=False):

        if reset:
            self.credentials['user_accounts'][username]['failed_login_attempts'] = 0
        else:
            self.credentials['user_accounts'][username]['failed_login_attempts'] += 1

    def execute_login(self, username: Optional[str]=None, token: Optional[dict]=None):
        if username:
            st.session_state['username'] = username
            st.session_state['name'] = self.credentials['user_accounts'][username]['name']
            st.session_state['authentication_status'] = True
            self._record_failed_login_attempts(username, reset=True)
            self.credentials['user_accounts'][username]['logged_in'] = True
        elif token:
            st.session_state['username'] = token['username']
            st.session_state['name'] = self.credentials['user_accounts'][token['username']]['name']
            st.session_state['authentication_status'] = True
            self.credentials['user_accounts'][token['username']]['logged_in'] = True
        

class Authenticate:
    """
    This class will create login, logout, register user, reset password, forgot password, 
    forgot username, and modify user details widgets.
    """
    def __init__(self, credentials: dict, cookie_name: str, cookie_key: str,
                 cookie_expiry_days: float=30.0, pre_authorized: Optional[list]=None,
                 validator: Optional[Validator]=None):

        self.authentication_handler     =   AuthenticationHandler(credentials,
                                                                  pre_authorized,
                                                                  validator)
        self.cookie_handler             =   CookieHandler(cookie_name,
                                                          cookie_key,
                                                          cookie_expiry_days)

    def login(self, max_concurrent_users: Optional[int]=None,
              max_login_attempts: Optional[int]=None) -> tuple:

        if not st.session_state['authentication_status']:
            token = self.cookie_handler.get_cookie()
            if token:
                self.authentication_handler.execute_login(token=token)
            time.sleep(0.7)

        if not st.session_state['authentication_status']:
            login_form = st.form('Login')

            login_form.subheader('Login')
            Account_No = login_form.text_input('Account No')
            password = login_form.text_input('Password', type='password')
                                                
            if login_form.form_submit_button('Login'):
                if Account_No.isdigit():
                    Account_No = int(Account_No)
                else:
                    raise LoginError
                
                if self.authentication_handler.check_credentials(Account_No, password):
                    
                    self.authentication_handler.execute_login(username=Account_No)
                    self.cookie_handler.set_cookie()

        return (st.session_state['name'], st.session_state['authentication_status'],
                st.session_state['username'])

    def logout(self, button_name: str='Logout'):

        if st.button(button_name):
            self.authentication_handler.execute_logout()
            self.cookie_handler.delete_cookie()


    def register_user(self, isAdmin: bool=False) -> tuple:

        register_user_form = st.form('Register user')

        register_user_form.subheader("Register User")
        name = register_user_form.text_input("Full Name")
        address = register_user_form.text_area('Address')
        mobile_no = register_user_form.text_input('Mobile No')
        email = register_user_form.text_input('Email')

        account_type = register_user_form.selectbox(
                        "Account Type",
                        ("Admin", "Current", "Savings") if not isAdmin else ("Admin",),
                        index=0 if isAdmin else None,
                        disabled=isAdmin
        )

        date_of_birth = register_user_form.date_input(
                        "Date of Birth",
                        min_value=datetime(1900, 1, 1),
                        max_value=datetime.now(),
                        format="DD/MM/YYYY"
        )

        id_proof = register_user_form.selectbox(
                        "ID Proof",
                        ("Aadhar Card", "Driving Lisence", "PAN Card"),
                        index=None
        )

        password = register_user_form.text_input('Password', type='password')
        password_repeat = register_user_form.text_input('Repeat password',type='password')

        if register_user_form.form_submit_button('Register'):
            return self.authentication_handler.register_user(password, password_repeat, name, email, mobile_no, 
                                                      account_type, address, date_of_birth, id_proof)

            

    def reset_password(self, username: str) -> bool:

        st.title('Reset password')

        reset_password_form = st.form('Reset password')

        password = reset_password_form.text_input('Current password', type='password')
        new_password = reset_password_form.text_input('New password', type='password')
        new_password_repeat = reset_password_form.text_input('Repeat password', type='password')

        if reset_password_form.form_submit_button('Reset'):
            if self.authentication_handler.reset_password(username, password, new_password,
                                                          new_password_repeat):
                return True
            
        return None
    
    def transaction(self, account_no) -> None:

        st.title("Make Transaction")
        transaction = Transaction(account_no, self.authentication_handler.credentials)

        try:
            deposit_form = st.form("Deposit", clear_on_submit=True)
            deposit = deposit_form.number_input("Enter Amount to Deposit", 0, step=50)
            if deposit_form.form_submit_button("Deposit"):
                transaction.deposit(deposit)

            withdraw_form = st.form("Withdraw", clear_on_submit=True)
            withdraw = withdraw_form.number_input("Enter Amount to Withdraw", 0, step=50)
            if withdraw_form.form_submit_button("Withdraw"):
                transaction.withdraw(withdraw)

        except ValueError as e:
            st.error(e)

        finally:
            st.subheader(f"Balance Avaliable ${transaction.balance:,.2f}")


class Transaction:

    def __init__(self, account_no, credentials) -> None:
        self.account = account_no
        self.mode = None
        self.credentials = credentials

    @property
    def balance(self):
        return self.credentials['user_details'][self.account]['balance']
    
    def deposit(self, amount):
        if 0 <= amount:
            self.mode = 'Deposit'
            self.transaction(amount)

        else:
            raise ValueError("Invaid Amount")
        
    def withdraw(self, amount):
        if 0 <= amount <= self.balance:
            self.mode = 'Withdraw'
            self.transaction(-amount)

        else:
            raise ValueError("Insufficitent balance" if amount > 0 else "Invaid Amount")
        
    def transaction(self, amount):
        before = self.balance
        self.credentials['user_details'][self.account]['balance'] += amount
        after = self.balance

        date = f"{datetime.now():%b %d %Y %H:%M:%S}"
        self.credentials['user_details'][self.account]['transactions'][date] = {

            'action': self.mode,
            'before amount': before,
            'after amount': after

        }
        
