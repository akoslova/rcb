# RCB Mode: A slightly different approach to the SCB 

Inspired by the Secure Codebook (SCB) mode of operation, the **Randomised Codebook (RCB)** modifies the SCB slightly in order to achieve even better security with neglible cost of less correctness. 
The SCB was described by ETH Zürich researcher Fabio Banfi in a paper appearing in [IACR Transactions on Symmetric Cryptology, Volume 2022, Issue 4](https://tosc.iacr.org/index.php/ToSC/article/view/9970), 
and it is the first length-preserving encryption scheme that does achieve semantic security while allowing for imperfect decryption. Those imperfections happen with only negligible 
probability if the parameter tao and sigma necessary for the mode are chosen with care. ... explain how RCB is different

## SCB & RCB Parameters

## Code
### How to run the Code
Now that we have the requirements file, you can see that it consists of a long list of different packages.

To work with the packages, you have to install them. You can do this by using the command prompt or terminal.
pip install -r requirements.txt

## Notice
The code is provided without any warranty and has not been written with efficiency in mind.

Important: Currently, scb.c uses the input key as both the block cipher key $K_1$ and the pad key $K_2$. This clearly should be avoided.
