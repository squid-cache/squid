// Money.h
#ifndef MONEY_H
#define MONEY_H

#include <string>
#include <stdexcept>

class IncompatibleMoneyError : public std::runtime_error
{
public:
   IncompatibleMoneyError() : std::runtime_error( "Incompatible moneys" )
  {
  }
};


class Money
{
public:
  Money( double amount, std::string currency )
    : m_amount( amount )
    , m_currency( currency )
  {
  }

  double getAmount() const
  {
    return m_amount;
  }

  std::string getCurrency() const
  {
    return m_currency;
  }

  bool operator ==( const Money &other ) const
  {
    return m_amount == other.m_amount  &&  
           m_currency == other.m_currency;
  }

  bool operator !=( const Money &other ) const
  {
    return !(*this == other);
  }

  Money &operator +=( const Money &other )
  {
    if ( m_currency != other.m_currency )
      throw IncompatibleMoneyError();

    m_amount += other.m_amount;
    return *this;
  }

private:
  double m_amount;
  std::string m_currency;
};

#endif
