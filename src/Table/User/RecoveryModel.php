<?php
namespace Pyncer\Snyppet\Access\Table\User;

use DateInterval;
use DateTime;
use DateTimeInterface;
use Pyncer\Data\Model\AbstractModel;
use Pyncer\Utility\Token;

use function Pyncer\code as pyncer_code;
use function Pyncer\date_time as pyncer_date_time;

use const Pyncer\DATE_TIME_FORMAT as PYNCER_DATE_TIME_FORMAT;
use const Pyncer\Snyppet\Access\RECOVERY_CODE_LENGTH as PYNCER_ACCESS_RECOVERY_CODE_LENGTH;
use const Pyncer\Snyppet\Access\RECOVERY_TOKEN_EXPIRATION as PYNCER_ACCESS_RECOVERY_TOKEN_EXPIRATION;

class RecoveryModel extends AbstractModel
{
    public function getUserId(): int
    {
        return $this->get('user_id');
    }
    public function setUserId(int $value): static
    {
        $this->set('user_id', $value);
        return $this;
    }

    public function getToken(): string
    {
        return $this->get('token');
    }
    public function setToken(string $value): static
    {
        $this->set('token', $value);
        return $this;
    }

    public function getCode(): string
    {
        return $this->get('code');
    }
    public function setCode(string $value): static
    {
        $this->set('code', $value);
        return $this;
    }

    public function getExpirationDateTime(): DateTime
    {
        $value = $this->get('expiration_date_time');
        return pyncer_date_time($value);
    }
    public function setExpirationDateTime(string|DateTimeInterface $value): static
    {
        if ($value instanceof DateTimeInterface) {
            $value = $value->format(PYNCER_DATE_TIME_FORMAT);
        }
        $this->set('expiration_date_time', $value);
        return $this;
    }

    public function getAttempts(): int
    {
        return $this->get('attempts');
    }
    public function setAttempts(int $value): static
    {
        $this->set('attempts', $value);
        return $this;
    }

    public static function getDefaultData(): array
    {
        $dateTime = pyncer_date_time();
        $dateTime->add(new DateInterval('PT' . PYNCER_ACCESS_RECOVERY_TOKEN_EXPIRATION . 'S'));
        $dateTime = $dateTime->format(PYNCER_DATE_TIME_FORMAT);

        return [
            'id' => 0,
            'user_id' => 0,
            'token' => strval(new Token()),
            'code' => pyncer_code(PYNCER_ACCESS_RECOVERY_CODE_LENGTH),
            'expiration_date_time' => $dateTime,
            'attempts' => 0,
        ];
    }
}
