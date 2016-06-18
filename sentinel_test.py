'''
The program consisted of three classes:
AESChiper- Responsible for data encryption
Account - bank account platform
Bank - Director of the bank in practice

The program simulates a bank administration so required confidentiality data and maximum security (as much as possible in a small project)

The general principle of this program: reading from a file, removing encryption,
  data processing to recognize platform and back - encryption and write to the file.

Management and workers password Verified without decryption for greater security.

It should be noted that I took the encryption algorithms from the internet and a little bit played with them to match
 them to my code.

The main password is "bank"

Enjoy!
'''

import datetime
import time
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import errno
import uuid
class AESCipher(object):
    """
    A classical AES Cipher. Can use any size of data and any size of password thanks to padding.
    Also ensure the coherence and the type of the data with a unicode to byte converter.
    """
    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()
    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('ISO-8859-1'))
        if isinstance(data, u_type):
            return data.encode('ISO-8859-1')
        return data

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * AESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('ISO-8859-1')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('ISO-8859-1')


class Account:
    def __init__(self,n_password,n_balance = 0,n_type='regular', n_creditFacility = 0):
        self.password=n_password
        self.balance=n_balance
        self.accType=n_type
        self.creditFacility=n_creditFacility

    def __repr__(self):
        return '{0} {1} {2} {3}'.format(self.password, self.balance, self.accType, self.creditFacility)

    def __str__(self):
        return 'password: {0} balance: {1} type:{2} credit:{3}'.format(self.password, self.balance, self.accType, self.creditFacility)

    def __len__(self):
        "return length of repr string for the encryption"
        return len(self.__repr__())

class Bank:
    def __init__(self):
        '''CTOR
           Initializes class variables.
           Loading: commission list,accountType list, active acc list.
        '''
        try:
            self.__bank_password = self.__validation_root_password(raw_input('enter management password:'))
            self.__commission = self.__load_double_list('commission')
            self.__bank_profit = 0
            self.__accountTypes = self.__load_double_list('accountTypes')
            self.__active_acc = None
            self.__acc_now = None
            self.__worker = None
            self.__load_active_acc()
        except IOError, io_error:
            cond1= io_error.errno == errno.ENOENT
            cond2= io_error.filename == 'type of acc'
            cond3= io_error.filename == 'root password'
            cond4= io_error.filename == 'active_acc'
            cond5= io_error.filename == 'commission file'

            if cond1 and (cond2 or cond3 or cond4 or cond5):
                raise KeyboardInterrupt("file: '{}'  not found! you can't run the Bank without this file!".format(io_error.filename))

    def __del__(self):
        '''Ctor
           writes updated data to files.'''
        try:
            self.__write_list(self.__accountTypes,'type list')
            self.__write_list(self.__commission,'commission file')
            self.__update_bank_profit()
            self.logout()
        except AttributeError:
            pass

    def deposit(self,num):
        "verifies proper amount, gett approval for the fee from customerand deposited to account"
        try:
            commission = self.__commission_calculation('deposit')
            cond1 = int(num) > 0
            cond2 = self.__customer_consent_fee(commission)
            if cond1 and cond2:
                self.__acc_now.balance = float(self.__acc_now.balance) + float(num - commission)
                self.__bank_profit = float(self.__bank_profit) + float(commission)
                print(
                '''Deposit succeeded!\n Your balance is:{0}.\nfor this action taken you a fee of {1} NIS. '''.format(
                    self.__acc_now.balance, commission))
            elif not cond1:
                raise ValueError("can't deposit negative amaount ")
            elif not cond2:
                return
        except ValueError, error:
            print error.message+"\n try again"
            self.deposit(raw_input('press deposit amount '))

    def withdraw(self,num):
        "verifies proper amount, get approval for the fee from customer and draw from account"
        try:
            commission = self.__commission_calculation('withdraw')
            cond1 = self.__customer_consent_fee(commission)  # agree to commission
            cond2 = num >= 0
            cond3 = float(self.__acc_now.balance) - (num + commission) >= (0 - int(self.__acc_now.creditFacility))
            if cond1 and cond2 and cond3:
                self.__acc_now.balance = float(self.__acc_now.balance) - (num + commission)
                self.__bank_profit = int(self.__bank_profit) + commission
                print("Drawing succeeded! Your balance is:{0}\n"
                      "for action taken you a fee of {1} NIS. ".format(self.__acc_now.balance, commission))
                if float(self.__acc_now.balance) < 0:
                    commission = self.__commission_calculation('overdraft')
                    self.__acc_now.balance = int(self.__acc_now.balance) - (commission)
                    self.__bank_profit = int(self.__bank_profit) + commission
                    print (
                    "Your account entered overdraft. \n Consequently taken you a fee of: {} NIS".format(commission))
            elif not cond1:
                return
            elif not cond2:
                raise ValueError("can't deposit negative amaount ")
            elif not cond3:
                print("sorry! You don't have enough money!")
        except ValueError,error:
            print error.message+"\n try again"
            self.withdraw(raw_input('press withdraw amount'))

    def login(self , password):
        "login to acc. updata varible acc_now and active_acc list"
        self.__load_active_acc()
        f=open("active_acc","r+")#prevent simultaneous update
        attempts = 1
        while True:
            if password in self.__active_acc:#if active
                print ("you can not connect active account.")
            else:
                acc=self.__check_if_exists(password)
                if acc == False:
                    print("wrong password \n")
                else:
                    self.__acc_now= acc
                    self.__active_acc.append(acc.password)
                    f.close()
                    self.__write_list(self.__active_acc,'active_acc')
                    return
            attempts += 1
            if attempts == 4:
                print ("Hired three incorrect passwords.\n"
                       "The system come back in half a minute.")
                time.sleep(30)
            password = raw_input('Enter your new password')

    def logout(self):
        "logout from account and update active_acc list "
        self.__write_account(self.__acc_now)
        self.__load_active_acc()
        self.__active_acc.remove(self.__acc_now.password)
        self.__acc_now =None
        self.__write_list(self.__active_acc,'active_acc')

    def __encrypt(self, password, acc):
        ''' encrypt with password that gets'''
        cipher = AESCipher(password)
        return cipher.encrypt(acc.__repr__())

    def __decrypt(self, password, en_obj):
        ''' decrypting with password that gets'''
        try:
            cipher = AESCipher(password)
            decrypted = cipher.decrypt(en_obj)
            return decrypted
        except ValueError:
            return ' , '

    def add_worker(self):
        " check access permissions , add worker, write to file."
        self.__validation_root_password(raw_input('enter management password:'))
        worker_pass = raw_input('enter worker password:')
        hashed_pass = self.__check_return_worker_password(worker_pass)
        if hashed_pass == True:
            print ('Works existing in system!')
            return
        else:
            print ('creates worker. password: {}'.format(worker_pass))
            f = open('bank worker password', 'a')
            f.write(hashed_pass)
            f.close()





    def delete_worker(self):
        "check access permission, delete worker and updates the file "
        self.__validation_root_password(raw_input('enter management password:'))
        tmp = ''
        exists_flag = False
        worker_pass = raw_input('enter worker password to delete:')
        f = open('bank worker password', 'r+')
        while True:
            hashed_password = f.read(97)
            if hashed_password == '':  # end file
                break
            else:
                password, salt = hashed_password.split(':')
                new_password = hashlib.sha256(salt.encode() + worker_pass.encode()).hexdigest()
                if password != new_password:  # is not the password for deletion
                    tmp += hashed_password
                    exists_flag = True
        f.close()
        if exists_flag:
            f = open('bank worker password', 'w')
            f.write(tmp)
            f.close()
            print "worker: {} was deleted".format(worker_pass)
        else:
            print ('worker with password {} not exists!.'.format(worker_pass))

    def create_acc(self):
        "create account and write to file"
        if self.__worker!=None:
            try:
                password = self.__check_return_password(raw_input('enter account password:'))
                credit = raw_input('enter credit facility ')
                credit=int(credit)
                print('select type:')
                num_of_types = self.__type_account_menu()
                selection = self.range_test(raw_input(), num_of_types - 1, 0)
                acc_type = self.__accountTypes[selection][0]
                acc = Account(password, 0, acc_type, credit)
                print ('account: {} was created!'.format(acc))
                self.__write_account(acc)
            except ValueError:
                print "{} is not a number! \n try again..".format(credit)
                self.create_acc()

    def delete_acc(self):
        '''delete account
           check if the account in active_acc list and if exists acc with this password.
            if not, print a message accordingly.'''
        exists_flag = False
        if self.__worker!=None:
            exists_flag = False
            password = raw_input('enter account password:')
            if password in self.__active_acc:
                print ("can't delete active account!")
                return
            f = open('account_file', 'r')
            en_data = f.read()
            en_data = str(en_data)
            f.close()
            f = open('account_file', 'w')  # close and open for  delete all file data
            for i in range(0, len(en_data), 64):
                if password != self.__acc_from_string(self.__decrypt(self.__bank_password, en_data[i:i + 64])).password:
                    f.write(en_data[i:i + 64])
                else:
                    exists_flag = True
            f.close()
            if not exists_flag:
                print "account with same password not exists!"
            else:
                print "{} was deleted!".format(password)

    def __validation_root_password(self,user_password):
        '''confirm management password '''
        while True:
            f = open('root password', 'r')
            passw= f.read(97)
            passw, salt = passw.split(':')
            if passw == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest():
                f.close()
                return user_password

            user_password=raw_input('wrong password! \n try again..')

    def __check_return_worker_password(self, user_password):
        "check if get current worker password. if yes - return True else return hash on the password "
        if user_password == self.__bank_password:
            return True
        f = open('bank worker password', 'r')
        while True:
            try:
                hashed_password = f.read(97)
                if hashed_password == '':#eof
                    f.close
                    print('no worker with this password..')
                    return self.__hash_worker_password(user_password)
                password, salt = hashed_password.split(':')
                new_password = hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()
                if  password == new_password :
                    f.close()
                    return True
            except ValueError:
                pass
            except SyntaxError, error:
                if 'Non-ASCII' in error.message:
                    print ('unknow charter! try again')


    def __hash_worker_password(self,password):
        "hash worker password"
        # uuid is used to generate a random number
        salt = uuid.uuid4().hex
        return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt

    def in_out_worker(self):
        "responsible on login \ logout of worker"
        if self.__worker == None:
            password = raw_input('enter worker password')
            if self.__check_return_worker_password(password) == True:
                self.__worker = password
        else:
            self.__worker = None



    def __write_account(self, acc):
        " encrypt and write account to file (replacing the old If available(update))"
        f = open('account_file', 'r+')
        en_data = f.read()
        en_data = str(en_data)
        f.seek(0)
        for i in range(0, len(en_data), 64):
            if acc.password != self.__acc_from_string(self.__decrypt(self.__bank_password, en_data[
                                                                                     i:i + 64])).password:  # if not same password we dont need replace with new
                f.write(en_data[i:i + 64])
        f.write(self.__encrypt(self.__bank_password, acc.__repr__()))

    def __write_list(self, list, file_name):
        "get list and file name , encrypt and write to file "
        try:
            f = open(file_name, 'w')
            f.write(self.__encrypt(self.__bank_password, list))
            f.close()
        except WindowsError:
            print "Writing data to a file was failed. try again in five seconds"
            time.sleep(5)
            self.__write_list(list, file_name)

    def __load_active_acc(self):
        "load active_acc list from file"
        try:
            f = open('active_acc', 'r')
            enc_list = f.read()
            f_list= self.__decrypt(self.__bank_password,enc_list)
            self.__active_acc = f_list.encode('utf-8').replace('(', '').replace(')', '').replace(',', '').replace("'", "").replace("[", "").replace("]", "").split()
        except ValueError:
            self.__active_acc=[]

    def __load_double_list(self,kind_of_list):
        "get kind of list,read encrypt list, decrypt and return the list "
        if kind_of_list == 'accountTypes':
            file_name = 'type of acc'
        elif kind_of_list == 'commission':
            file_name = 'commission file'
        try:
            chiper = AESCipher(self.__bank_password)
            f = open(file_name, 'r')
            en_data = f.read()
            data = chiper.decrypt(en_data)
            data = data.encode('utf-8').replace('(', '').replace(')', '').replace(',', '').replace("'", "").replace("[",
                                                                                                                    "").replace(
                "]", "").split()
            tmp = []
            for i in range(0, len(data), 2):
                tmp.append([data[i], data[i + 1]])
            f.close
            return tmp
        except ValueError:
            self.__accountTypes=[]

    def update_commision(self):
        " responsible to update commssion"
        try:
            self.__validation_root_password(raw_input('enter management password:'))
            print('select commission:')
            num_of_types = self.__commission_menu()
            up_num = self.range_test(raw_input(), num_of_types - 1, 0)
            new_commission = int(raw_input('enter new commission'))
            self.__commission[up_num][1] = new_commission
            self.__write_list(self.__commission, 'commission file')
            print("commission {0} was update to: {1}".format(self.__commission[up_num][0], self.__commission[up_num][1]))
        except ValueError:
            new_commission = raw_input("commission must be number! \n"
                                       "try again")
            self.update_commision()

    def update_account_type(self):
        "responsible to create , delete and update types of account"
        self.__validation_root_password(raw_input('enter management password:'))
        selection = self.range_test(
            raw_input("1. create new type \n"
                      "2.delete type \n"
                      "3.update discaount type \n"
                      " 4. go out"), 4, 1)
        if selection == 1:
            num_of_types = len(self.__accountTypes)
            name = raw_input(" enter type name:")
            discount = self.range_test(raw_input('enter precent of discount '), 100, 0)
            discount = (discount / 100) + (discount % 100)
            tmp = [name, discount]
            self.__accountTypes.append(tmp)
            print "{0} was created! discount{1}".format(name, discount)
        elif selection == 2:
            print('select type:')
            num_of_types = self.__type_account_menu()
            del_num = self.range_test(raw_input(), num_of_types - 1, 0)
            del self.__accountTypes[del_num]
        elif selection == 3:
            print('select type:')
            num_of_types = self.__type_account_menu()
            up_num = self.range_test(raw_input(), num_of_types - 1, 0)
            discount = self.range_test(raw_input('enter precent of discount '), 100, 0)
            discount = (discount / 100) + (discount % 100)
            self.__accountTypes[up_num][1] = discount
            print("updated {0} type! Discount percent: {1}".format(self.__accountTypes[up_num][0],
                                                                   self.__accountTypes[up_num][1]))
        elif selection == 4:
            return

    def __update_bank_profit(self):
        " read profit from file, decrypt, add the profit from last operation, encrypt and write to file "
        f = open('bank profit', 'r+')
        tmp = f.read()
        profit = str(self.__decrypt(self.__bank_password, tmp).replace("'", "").replace('''"''', ""))
        profit = int(profit)
        profit += int(self.__bank_profit)
        en_profit = self.__encrypt(self.__bank_password, str(profit))
        f.seek(0)
        f.write(en_profit)
        f.close()
        self.__bank_profit = 0

    def __customer_consent_fee(self,commission):
        "take consent from customer for commission"
        if commission == 0:
            print "You have 100% discount on this operation!"
        self.__cunstumer_confirm_menu(commission)
        answer = self.range_test(raw_input(),2,1)
        if answer == 1:
            return True
        else:
            return False

    def __commission_calculation(self,commission_type):
        "return calculation of commission"
        i=0
        discaount = 0
        for l in self.__accountTypes:
            if l[0] == self.__acc_now.accType:
                discaount = float(l[1])
                break
        for l in self.__commission:
            if l[0]==commission_type:
                i+=1

        return float(self.__commission[i][1]) * (1 - discaount)

    def print_bank_profit(self):
        "read decrypt an print bank profit "
        self.__update_bank_profit()
        f = open('bank profit', 'r')
        tmp = f.read()
        profit = self.__decrypt(self.__bank_password, tmp)
        print('Bank profits:{0} \nAdjusted :{1}'.format(profit,datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")))

    def print_acc_now_balance(self):
        print ("your balance is: {}".format(self.__acc_now.balance))

    def __check_return_password(self,password):
        "Checks that not exists same passowrd and make sure that it's valid password"
        cond1= ')' in password
        cond2= '(' in password
        cond3= "'" in password
        cond4= ',' in password
        while cond1 or cond2 or cond3 or cond4:
            password = raw_input("The password can not contain these characters ( ) ' ,  \n try new password: ")
        while self.__check_if_exists(password) != False:  # need =FALSE because if true return acc
            password = raw_input('''there is an account with same password \ntry new password: ''')
        return password

    def __check_if_exists(self, password):
        "check if there is account with same password. if exists return acc else false"
        f = open('account_file', 'r')
        en_data = f.read()
        en_data = str(en_data)
        f.close()
        for i in range(0, len(en_data), 64):
            acc=self.__acc_from_string(self.__decrypt(self.__bank_password, en_data[i:i + 64]))
            if password == acc.password:
                return acc
        return False

    def __acc_from_string(self,string):
        "set strint split, create and return acc"
        string=str(string)
        string=string.replace("'","")
        tmp = string.split()
        return Account(tmp[0], tmp[1], tmp[2], tmp[3])

    def if_worker_cennected(self):
        "if there is connected worker return true , elsr return false"
        if self.__worker==None:
            return False
        else:
            return True

    def range_test(self,selection,bigger,smaller):
        "check if  selection in defined range"
        while True:
            try:
                cond = int(smaller) <= int(selection) <=int(bigger)
                if cond:
                    return int(selection)
                else:
                    print("your selection is worng \n!"
                          "try again!")
                    selection = raw_input()
            except ValueError:
                print ('Inserted an incorrect value! \n'
                       ' Try again..')
                selection=raw_input()

    def __type_account_menu(self):
        "print account types and return num of types "
        i=0
        for l in self.__accountTypes:
            print('{0}.  {1}'.format(i,l[0]))
            i+=1
        return i

    def __commission_menu(self):
        "print account types and return how many type are there "
        i = 0
        for l in self.__commission:
            print('{0}.  {1}'.format(i, l[0]))
            i += 1
        return i

    def __cunstumer_confirm_menu(self,commission):
        "print menu of cunstumer confirm for fee"
        print("for this action will be taken you a fee amounting to {0} NIS .\n"
              "1. confirm. \n"
              "2. not confirm").format(commission)







 ########################################## main  ####################################################################


def main_menu():
    "print main menu"
    print("1. Login \n"
          "2.Management \n"
          "3.Quit")


def account_menu():
    "print account menu"
    print("1. Check balance\n"
          "2. Deposit \n"
          "3. Withdraw \n"
          "4. Logoff")


def management_menu():
    print("1. create account \n"
          "2. delete_account \n"
          "3. add worker \n"
          "4. delete worker\n"
          "5.get bank profit \n"
          "6. update types\n"
          "7. update commission \n"
          "8. Logoff ")


while True:
    try:
        bank = Bank()
        try:
            while True:
                main_menu()
                option = bank.range_test(raw_input(), 3, 1)
                if option == 1:
                    bank.login(raw_input('Enter your password'))
                    while True:
                        account_menu()
                        acc_option = bank.range_test(raw_input(), 4, 1)
                        if acc_option == 1:
                            bank.print_acc_now_balance()
                        elif acc_option == 2:
                            bank.deposit(int(raw_input('Press deposit amount')))
                        elif acc_option == 3:
                            bank.withdraw(int(raw_input('Press withdraw amount')))
                        elif acc_option == 4:
                            bank.logout()
                            break

                elif option == 2:
                    bank.in_out_worker()  # sign worker
                    if not bank.if_worker_cennected():
                        pass
                    else:
                        while True:
                            management_menu()
                            management_option = bank.range_test(raw_input(), 8, 1)
                            if management_option == 1:
                                bank.create_acc()
                            elif management_option == 2:
                                bank.delete_acc()
                            elif management_option == 3:
                                bank.add_worker()
                            elif management_option == 4:
                                bank.delete_worker()
                            elif management_option == 5:
                                bank.print_bank_profit()
                            elif management_option == 6:
                                bank.update_account_type()
                            elif management_option == 7:
                                bank.update_commision()
                            elif management_option == 8:
                                bank.in_out_worker()  # sign out from worker
                                break



                elif option == 3:
                    break

        except ValueError, error:
            print error.message + "\n start from beginning"
            bank.logout()
            continue

        except IOError, io_error:
            bank.logout()
            cond1 = io_error.errno == errno.ENOENT
            cond2 = io_error.filename == 'bank profit'
            cond3 = io_error.filename == 'bank worker password'
            cond4 = io_error.filename == 'account_file'
            if cond1 and (cond2 or cond3 or cond4):
                print(
                "file: {} Not found! You can not access some databases and data change will not be listed in!".format(
                    io_error.filename))
                tmp = open(io_error.filename, 'w')
                tmp.close()  # what to vdo if no such file
        except KeyboardInterrupt, error:
            print error.message
            break

        except WindowsError, error:
            bank.logout()
            print error.message + "\n restart in five seconds"
            time.sleep(5)
            time.sleep(5)

    except AttributeError:
        pass
    except:
        print ('unknow charter! access denied!')



print('thanks and have a good day!')







